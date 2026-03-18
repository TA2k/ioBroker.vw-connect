.class public final synthetic Lfv/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lko/m;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:[Ljo/d;


# direct methods
.method public synthetic constructor <init>([Ljo/d;I)V
    .locals 0

    .line 1
    iput p2, p0, Lfv/q;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lfv/q;->e:[Ljo/d;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()[Ljo/d;
    .locals 1

    .line 1
    iget v0, p0, Lfv/q;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lfv/q;->e:[Ljo/d;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v0, Lfv/h;->a:[Ljo/d;

    .line 9
    .line 10
    return-object p0

    .line 11
    :pswitch_0
    sget-object v0, Lfv/h;->a:[Ljo/d;

    .line 12
    .line 13
    return-object p0

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
