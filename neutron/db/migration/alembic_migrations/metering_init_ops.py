# Copyright 2014 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

# Initial operations for the metering service plugin


from alembic import op
import sqlalchemy as sa


direction = sa.Enum('ingress', 'egress',
                    name='meteringlabels_direction')


def upgrade():
    op.create_table(
        'meteringlabels',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=1024), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'meteringlabelrules',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('direction', direction, nullable=True),
        sa.Column('remote_ip_prefix', sa.String(length=64), nullable=True),
        sa.Column('metering_label_id', sa.String(length=36), nullable=False),
        sa.Column('excluded', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['metering_label_id'],
                                ['meteringlabels.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))


def downgrade():
    op.drop_table('meteringlabelrules')
    op.drop_table('meteringlabels')
    direction.drop(op.get_bind(), checkfirst=False)
