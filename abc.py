import asyncio
import json
import time
from indy import pool, wallet, did, ledger, anoncreds
from indy.error import IndyError, ErrorCode      


async def ensure_previous_request_applied(pool_handle, checker_request):
    for _ in range(3):
        response = json.loads(await ledger.submit_request(pool_handle, checker_request))
        if response.get('op', '') == 'REPLY':
            return json.dumps(response)
        time.sleep(5)

async def get_cred_def(pool_handle, did, cred_def_id):
    # timestamp = int(time.time())
    get_cred_def_request = await ledger.build_get_cred_def_request(did, cred_def_id)
    get_cred_def_response = \
        await ensure_previous_request_applied(pool_handle, get_cred_def_request,
                                                lambda response: response['result']['data'] is not None)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)

async def create_wallet(identity):
    print("Creating wallet for identity: {}".format(identity['name']))
    try:
        await wallet.create_wallet(identity['wallet_config'], identity['wallet_credentials'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            print("Wallet already exists for identity: {}".format(identity['name']))
        else:
            raise
    print("\n")

async def setup_indy_pool():
    pool_name = "indy_pool"
    pool_genesis_txn_path = "genesis_txn.txn"  
    try:
        await pool.set_protocol_version(2)
        pool_config = json.dumps({"genesis_txn": pool_genesis_txn_path})
        await pool.create_pool_ledger_config(pool_name, pool_config)
        print("Indy Pool configuration created.")
    except IndyError as e:
        if e.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            print("Indy Pool configuration already exists.")
            pass
    print("pool_name: ", pool_name)
    print("pool_genesis_txn_path: ", pool_genesis_txn_path)
    print("\n")
    return pool_name

async def connect_to_pool(pool_name):
    try:
        pool_handle = await pool.open_pool_ledger(pool_name, None)
        print("Connected to the Indy Pool.")
        print("pool_handle: ", pool_handle)
        print("\n")
        return pool_handle  # Return the pool_handle
    except IndyError as e:
        print(f"Error: {e}")
        print("\n")
        return None  # Return None in case of an error

async def configure_steward(pool_handle):
    steward = {
        'name': 'Sovrin Steward',
        'wallet_config': json.dumps({'id': 'steward_wallet'}),
        'wallet_credentials': json.dumps({'key': 'steward_wallet_key'}),
        'pool': pool_handle,
        'did_seed': '000000000000000000000000Steward1'
    }

    try:
        await wallet.create_wallet(steward['wallet_config'], steward['wallet_credentials'])
        print("Steward wallet created.")
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            print("Steward wallet already exists.")
            pass
    steward['wallet_handle'] = await wallet.open_wallet(steward['wallet_config'], steward['wallet_credentials'])
    print("steward wallet_handle: ", steward['wallet_handle'])
    steward['did_info'] = json.dumps({'seed': steward['did_seed']})
    steward['did'], steward['verkey'] = await did.create_and_store_my_did(steward['wallet_handle'], steward['did_info'])
    print("Steward DID created.")
    # await wallet.close_wallet(steward['wallet'])
    print("steward did_info: ", steward['did_info'])
    print("\n")
    return steward


async def register_verinyms(pool_handle, steward, identities):
    # wallet_handle_list = []   # Create an empty list to store wallet handles
    for identity in identities:
        # Create and open the wallet
        wallet_config = json.loads(identity['wallet_config'])
        wallet_credentials = json.loads(identity['wallet_credentials'])
        await create_wallet(identity)
        identity['wallet_handle'] = await wallet.open_wallet(json.dumps(wallet_config), json.dumps(wallet_credentials))
        # wallet_handle_list.append(wallet_handle)
        # Generate DID and verkey
        (identity['did'], identity['verkey']) = await did.create_and_store_my_did(identity['wallet_handle'], "{}")

        # Build and submit the NYM request
        nym_request = await ledger.build_nym_request(steward['did'], identity['did'], identity['verkey'], None, identity.get('role', 'TRUST_ANCHOR'))
        # print("*****************")
        # print(pool_handle, wallet_handle, steward['did'], nym_request)
        # print("*****************")
        await ledger.sign_and_submit_request(pool_handle, identity['wallet_handle'], identity['did'], nym_request)

        # Close the wallet
        # await wallet.close_wallet(wallet_handle)

        print("Verinym registered for identity: {}".format(identity['name']))
        print(f"Identity: {identity['name']} - DID: {identity['did']}")
        print("\n")
    # return wallet_handle_list

async def create_and_store_schema(name, pool_handle, wallet_handle, did, schema): 

    print(name, " creates ", schema['name'], "credential definitioin ")
    schema_id, schema_json = await anoncreds.issuer_create_schema(did, schema['name'], schema['version'], json.dumps(schema['attributes']))
    schema_request = await ledger.build_schema_request(did, schema_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, did, schema_request)
    return schema_id, schema_json

async def register_credential_definition(name, pool_handle, wallet_handle, did, schema_id, schema_json, cred_def, schema):

    print(name, " creates and stores in wallet ", schema['name']," credential definition ")
    cred_def_id, cred_def_json = await anoncreds.issuer_create_and_store_credential_def(wallet_handle, did, schema_json, cred_def['tag'], cred_def['type'], json.dumps(cred_def['config']))
    print(name, " sends the ", schema['name'], " credential definition to ledger ")
    cred_def_request = await ledger.build_cred_def_request(did, cred_def_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, did, cred_def_request)
    print("\n")
    return cred_def_id, cred_def_json

async def issue_credentials(index, identities, type_, actor_name, pool_handle):
    print(f"{actor_name} creates {type_} credential offer")
    identities[index][f'{type_}_cred_offer'] = await anoncreds.issuer_create_credential_offer(identities[index]['wallet_handle'], identities[index][f'{type_}_cred_def_id'])
    print(f"{actor_name} sends {type_} Credential offer to Rajesh")
    identities[2][f'{type_}_cred_offer'] = identities[index][f'{type_}_cred_offer']
    print(f"Rajesh prepares {type_} credential request")
    cred_offer_object = json.loads(identities[2][f'{type_}_cred_offer'])
    identities[2][f'{type_}_schema_id'] = cred_offer_object['schema_id']
    identities[2][f'{type_}_cred_def_id'] = cred_offer_object['cred_def_id']

    print("Rajesh Create and stores master secret in Wallet")
    identities[2]['master_secret_id'] = await anoncreds.prover_create_master_secret(identities[2]['wallet_handle'], None)
    print(f"Rajesh gets {type_} credential definition from ledger")
    #(identities[2][f'{type_}_cred_def_id'], identities[2][f'{type_}_cred_def']) = await get_cred_def (pool_handle, identities[2]['did'], identities[2][f'{type_}_cred_def_id'])

    (identities[2][f'{type_}_cred_def_id'], identities[2][f'{type_}_cred_def']) = (
        identities[index][f'{type_}_cred_def_id'], identities[index][f'{type_}_cred_def']
    )

    print(f"Rajesh creates {type_} credential request for {actor_name}")
    (identities[2][f'{type_}_cred_request'], identities[2][f'{type_}_cred_request_metadata']) = await anoncreds.prover_create_credential_req(
        identities[2]['wallet_handle'], identities[2]['did'],
        identities[2][f'{type_}_cred_offer'],
        identities[2][f'{type_}_cred_def'],
        identities[2]['master_secret_id']
    )
    print(f"Rajesh sends {type_} credential Request to {actor_name}")

    # Over the Network
    identities[index][f"{type_}_cred_request"] = identities[2][f"{type_}_cred_request"]
    print(f"{actor_name} issues credential to Rajesh")
    print(f"{actor_name} creates {type_} credential for Rajesh")
    if index==0:
        identities[index][f'rajesh_{type_}_cred_values'] = json.dumps({
            'owner_first_name': {"raw": "Rajesh", "encoded": "1234567890"},
            'owner_last_name': {"raw": "Kumar", "encoded": "9876543210"},
            'address_of_property': {"raw": "Malancha Road, Kharagpur", "encoded": "5678901234"},
            'residing_since_year': {"raw": "2010", "encoded": "4321098765"},
            'property_value_estimate': {"raw": "2000000", "encoded": "3456789012"},
            'relation_to_applicant': {"raw": "Owner", "encoded": "6543210987"}
        })
    else:
        identities[index][f'rajesh_{type_}_cred_values'] = json.dumps({
            'student_first_name': {"raw": "Rajesh", "encoded": "1234567890"},
            'student_last_name': {"raw": "Kumar", "encoded": "9876543210"},
            'degree_name': {"raw": "Pilot Training Programme", "encoded": "5678901234"},
            'student_since_year': {"raw": "2022", "encoded": "4321098765"},
            'cgpa': {"raw": "8", "encoded": "3456789012"}
        })
    identities[index][f'{type_}_cred'], _, _ = await anoncreds.issuer_create_credential(
                                                                                        identities[index]['wallet_handle'], identities[index][f'{type_}_cred_offer'],
                                                                                        identities[index][f'{type_}_cred_request'],
                                                                                        identities[index][f'rajesh_{type_}_cred_values'], None, None
                                                                                    )
    print(f"{actor_name} sends {type_} credential to Rajesh")

    # Over the network
    identities[2][f'{type_}_cred'] = identities[index][f'{type_}_cred']
    print(f"Rajesh stores {type_} credential from {actor_name}")
    identities[2][f'{type_}_cred_def'] = identities[2][f'{type_}_cred_def']
    await anoncreds.prover_store_credential(identities[2]['wallet_handle'], None, identities[2][f'{type_}_cred_request_metadata'],
                                            identities[2][f'{type_}_cred'], identities[2][f'{type_}_cred_def'], None)





async def main():
    # Part A - Setup Indy Pool
    # part A utilises "setup_indy_pool()", "connect_to_pool()", "configure_steward()", and "register_verinyms()" functions

    print("\n\t\t\t***** Part-A *****\n\n")
    print("\t### Setting up Indy Pool ###\n")
    pool_name = await setup_indy_pool()
    print("\t### Connecting to Indy Pool ###\n")
    pool_handle = await connect_to_pool(pool_name)
    if pool_handle is None:
        print("Failed to connect to the pool.")
        return  # Exit the function if pool connection failed
    print("\t### Setting up Steward ###\n")
    steward = await configure_steward(pool_handle)

    identities = [
        {
            'name': 'Government',
            'role': 'TRUST_ANCHOR',
            'wallet_config': json.dumps({'id': 'government_wallet'}),
            'wallet_credentials': json.dumps({'key': 'government_wallet_key'})
        },
        {
            'name': 'NAA',
            'role': 'TRUST_ANCHOR',
            'wallet_config': json.dumps({'id': 'naa_wallet'}),
            'wallet_credentials': json.dumps({'key': 'naa_wallet_key'})
        },
        {
            'name': 'Rajesh',
            'role': None,  # Rajesh's role should be null or left undefined
            'wallet_config': json.dumps({'id': 'rajesh_wallet'}),
            'wallet_credentials': json.dumps({'key': 'rajesh_wallet_key'})
        },
    ]
    print("\t### Registering verinyms ###\n")
    await register_verinyms(pool_handle, steward, identities)

    # Part B - Define schemas and register credential definitions
    # part B utilises "create_and_store_schema()", and "register_credential_definition()" functions

    print("\n\t\t\t***** Part-B *****\n\n")
    property_details_schema = {
        'name': 'PropertyDetails',
        'version': '1.2',
        'attributes': ['owner_first_name', 'owner_last_name', 'address_of_property', 'residing_since_year', 'property_value_estimate', 'relation_to_applicant']
    }
    bonafide_student_schema = {
        'name': 'BonafideStudent',
        'version': '1.2',
        'attributes': ['student_first_name', 'student_last_name', 'degree_name', 'student_since_year', 'cgpa']
    }

    property_details_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {
            'support_revocation': False
        }
    }
    bonafide_student_cred_def = {
        'tag': 'TAG2',
        'type': 'CL',
        'config': {
            'support_revocation': False
        }
    }
    print("\t### Setting up credential schemas ###\n")
    # Create and store schemas on the ledger
    identities[0]['property_schema_id'], identities[0]['property_schema_json'] = await create_and_store_schema("Government", pool_handle, identities[0]['wallet_handle'], identities[0]['did'], property_details_schema)
    identities[1]['bonafide_schema_id'], identities[1]['bonafide_schema_json'] = await create_and_store_schema("NAA", pool_handle, identities[1]['wallet_handle'], identities[1]['did'], bonafide_student_schema)

    print("\n\t### Setting up  credential definitions ###\n")
    # Register credential definitions
    identities[0]['property_cred_def_id'], identities[0]['property_cred_def'] = await register_credential_definition("Government", pool_handle, identities[0]['wallet_handle'], identities[0]['did'], identities[0]['property_schema_id'], identities[0]['property_schema_json'], property_details_cred_def, property_details_schema)
    identities[1]['bonafide_cred_def_id'], identities[1]['bonafide_cred_def'] = await register_credential_definition("NAA", pool_handle, identities[1]['wallet_handle'], identities[1]['did'], identities[1]['bonafide_schema_id'], identities[1]['bonafide_schema_json'], bonafide_student_cred_def, bonafide_student_schema)

    # Part C - issuers issue credentials to Rajesh
    # part C utilises "issue_credentials()" function

    print("\n\t\t\t***** Part-C *****\n\n")

    await issue_credentials(0, identities, "property", "government", pool_handle)
    print("\n")
    await issue_credentials(1, identities, "bonafide", "naa", pool_handle)

    # Part D - CBDC Bank requests a “loan_application_proof_request”

    print("\n\t\t\t***** Part-D *****\n\n")
    
    proof_request = {
        'name': 'loan_application_proof_request',
        'version': '1.0',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name'
            },
            'attr2_referent': {
                'name': 'last_name'
            },
            'attr3_referent': {
                'name': 'degree_name',
                'restrictions': [{'cred_def_id': identities[1]['bonafide_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'student_since_year',
                'restrictions': [{'cred_def_id': identities[1]['bonafide_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'cgpa',
                'restrictions': [{'cred_def_id': identities[1]['bonafide_cred_def_id']}]
            },
            'attr6_referent': {
                'name': 'address_of_property',
                'restrictions': [{'cred_def_id': identities[0]['property_cred_def_id']}]
            },
            'attr7_referent': {
                'name': 'property_value_estimate',
                'restrictions': [{'cred_def_id': identities[0]['property_cred_def_id']}]
            },
            'attr8_referent': {
                'name': 'residing_since_year',
                'restrictions': [{'cred_def_id': identities[1]['bonafide_cred_def_id']}]
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'student_since_year',
                'p_type': '>=',
                'p_value': 2019,
                'restrictions': [{'cred_def_id': identities[1]['bonafide_cred_def_id']}]
            },
            'predicate2_referent': {
                'name': 'student_since_year',
                'p_type': '<=',
                'p_value': 2023,
                'restrictions': [{'cred_def_id': identities[1]['bonafide_cred_def_id']}]
            },
            'predicate3_referent': {
                'name': 'cgpa',
                'p_type': '>',
                'p_value': 6.0,
                'restrictions': [{'cred_def_id': identities[1]['bonafide_cred_def_id']}]
            },
            'predicate4_referent': {
                'name': 'property_value_estimate',
                'p_type': '>',
                'p_value': 800000,
                'restrictions': [{'cred_def_id': identities[0]['property_cred_def_id']}]
            }
        }
    }


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
