//! `SeaORM` Entity, @generated by sea-orm-codegen 1.0.1

use crate::time::Timestamp;
use crate::Id;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "snap_users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Id,
    #[sea_orm(unique)]
    pub u_id: Uuid,
    #[sea_orm(column_type = "Text", unique)]
    pub user_login: String,
    #[sea_orm(column_type = "Text")]
    pub user_nick: String,
    #[sea_orm(column_type = "Text")]
    pub password: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub email: Option<String>,
    pub active: bool,
    #[sea_orm(column_type = "Text")]
    pub active_token: String,
    #[sea_orm(column_type = "Text")]
    pub picture: String,
    pub create_time: Timestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::snap_user_token::Entity")]
    Token,
    #[sea_orm(has_many = "super::snap_device_group::Entity")]
    DeviceGroup,
}

impl Related<super::snap_user_token::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Token.def()
    }
}

impl Related<super::snap_device_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::DeviceGroup.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
