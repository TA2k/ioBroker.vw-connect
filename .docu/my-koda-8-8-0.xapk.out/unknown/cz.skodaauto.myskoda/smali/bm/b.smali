.class public final Lbm/b;
.super Lu01/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I

.field public f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lu01/h0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lbm/b;->e:I

    invoke-direct {p0, p1}, Lu01/n;-><init>(Lu01/h0;)V

    return-void
.end method

.method public constructor <init>(Lu01/h0;Ld01/d;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lbm/b;->e:I

    iput-object p2, p0, Lbm/b;->f:Ljava/lang/Object;

    .line 2
    invoke-direct {p0, p1}, Lu01/n;-><init>(Lu01/h0;)V

    return-void
.end method


# virtual methods
.method public A(Lu01/f;J)J
    .locals 1

    .line 1
    iget v0, p0, Lbm/b;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2, p3}, Lu01/n;->A(Lu01/f;J)J

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    return-wide p0

    .line 11
    :pswitch_0
    :try_start_0
    invoke-super {p0, p1, p2, p3}, Lu01/n;->A(Lu01/f;J)J

    .line 12
    .line 13
    .line 14
    move-result-wide p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    return-wide p0

    .line 16
    :catch_0
    move-exception p1

    .line 17
    iput-object p1, p0, Lbm/b;->f:Ljava/lang/Object;

    .line 18
    .line 19
    throw p1

    .line 20
    :pswitch_1
    :try_start_1
    invoke-super {p0, p1, p2, p3}, Lu01/n;->A(Lu01/f;J)J

    .line 21
    .line 22
    .line 23
    move-result-wide p0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 24
    return-wide p0

    .line 25
    :catch_1
    move-exception p1

    .line 26
    iput-object p1, p0, Lbm/b;->f:Ljava/lang/Object;

    .line 27
    .line 28
    throw p1

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public close()V
    .locals 1

    .line 1
    iget v0, p0, Lbm/b;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Lu01/n;->close()V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    iget-object v0, p0, Lbm/b;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Ld01/d;

    .line 13
    .line 14
    iget-object v0, v0, Ld01/d;->e:Lf01/d;

    .line 15
    .line 16
    invoke-virtual {v0}, Lf01/d;->close()V

    .line 17
    .line 18
    .line 19
    invoke-super {p0}, Lu01/n;->close()V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method
