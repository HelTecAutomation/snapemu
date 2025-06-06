//! `SeaORM` Entity, @generated by sea-orm-codegen 1.0.1

use crate::product::ShareType;
use crate::time::Timestamp;
use crate::Id;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "snap_device_authority")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Id,
    pub auth_creator: Id,
    pub device_id: Id,
    #[sea_orm(column_type = "Text")]
    pub share_type: ShareType,
    pub share_id: Id,
    pub owner: bool,
    pub manager: bool,
    pub modify: bool,
    pub delete: bool,
    pub share: bool,
    pub create_time: Timestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_one = "super::snap_devices::Entity")]
    Device,
}

impl Related<super::snap_devices::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Device.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
