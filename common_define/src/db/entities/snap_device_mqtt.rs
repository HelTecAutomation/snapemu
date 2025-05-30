//! `SeaORM` Entity, @generated by sea-orm-codegen 1.0.1

use crate::db::Eui;
use crate::Id;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "snap_device_mqtt")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Id,
    pub device_id: Id,
    #[sea_orm(column_type = "Text")]
    pub eui: Eui,
    #[sea_orm(column_type = "Text")]
    pub username: String,
    #[sea_orm(column_type = "Text")]
    pub password: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
