//! `SeaORM` Entity, @generated by sea-orm-codegen 1.0.1

use crate::time::Timestamp;
use crate::Id;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "snap_user_token")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Id,
    pub user_id: Id,
    #[sea_orm(column_type = "Text")]
    pub token: String,
    #[sea_orm(column_type = "Text")]
    pub token_type: String,
    pub enable: bool,
    pub expires_time: Timestamp,
    pub create_time: Timestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::snap_users::Entity",
        from = "Column::UserId",
        to = "super::snap_users::Column::Id"
    )]
    User,
}

impl Related<super::snap_users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
