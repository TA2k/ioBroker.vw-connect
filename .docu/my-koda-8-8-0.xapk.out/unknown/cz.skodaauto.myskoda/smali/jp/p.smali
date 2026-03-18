.class public final Ljp/p;
.super Lhr/t;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic i:I

.field public final synthetic j:Ljp/t;


# direct methods
.method public synthetic constructor <init>(Ljp/t;I)V
    .locals 0

    .line 1
    iput p2, p0, Ljp/p;->i:I

    .line 2
    .line 3
    iput-object p1, p0, Ljp/p;->j:Ljp/t;

    .line 4
    .line 5
    invoke-direct {p0, p1}, Lhr/t;-><init>(Ljp/t;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(I)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ljp/p;->i:I

    .line 2
    .line 3
    iget-object p0, p0, Ljp/p;->j:Ljp/t;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v0, Ljp/t;->m:Ljava/lang/Object;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljp/t;->c()[Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    aget-object p0, p0, p1

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_0
    new-instance v0, Ljp/s;

    .line 18
    .line 19
    invoke-direct {v0, p0, p1}, Ljp/s;-><init>(Ljp/t;I)V

    .line 20
    .line 21
    .line 22
    return-object v0

    .line 23
    :pswitch_1
    sget-object v0, Ljp/t;->m:Ljava/lang/Object;

    .line 24
    .line 25
    invoke-virtual {p0}, Ljp/t;->b()[Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    aget-object p0, p0, p1

    .line 30
    .line 31
    return-object p0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
