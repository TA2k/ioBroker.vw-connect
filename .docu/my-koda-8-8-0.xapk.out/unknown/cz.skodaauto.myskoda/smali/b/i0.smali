.class public final Lb/i0;
.super Lb/a0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic b:I

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lay0/k;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lb/i0;->b:I

    iput-object p1, p0, Lb/i0;->c:Ljava/lang/Object;

    const/4 p1, 0x1

    .line 2
    invoke-direct {p0, p1}, Lb/a0;-><init>(Z)V

    return-void
.end method

.method public constructor <init>(Lz9/y;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lb/i0;->b:I

    iput-object p1, p0, Lb/i0;->c:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 1
    invoke-direct {p0, p1}, Lb/a0;-><init>(Z)V

    return-void
.end method


# virtual methods
.method public final handleOnBackPressed()V
    .locals 1

    .line 1
    iget v0, p0, Lb/i0;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lb/i0;->c:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lz9/y;

    .line 9
    .line 10
    invoke-virtual {p0}, Lz9/y;->h()Z

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object v0, p0, Lb/i0;->c:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lay0/k;

    .line 17
    .line 18
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
