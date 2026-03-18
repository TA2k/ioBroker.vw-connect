.class public final Lg11/e;
.super Ll11/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Lj11/a;


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lg11/e;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance p1, Lj11/f;

    .line 10
    .line 11
    invoke-direct {p1}, Lj11/s;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lg11/e;->b:Lj11/a;

    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    new-instance p1, Lj11/z;

    .line 21
    .line 22
    invoke-direct {p1}, Lj11/s;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lg11/e;->b:Lj11/a;

    .line 26
    .line 27
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method private final j(Lk11/b;)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public a(Lk11/b;)V
    .locals 0

    .line 1
    iget p0, p0, Lg11/e;->a:I

    .line 2
    .line 3
    return-void
.end method

.method public c(Lj11/a;)Z
    .locals 1

    .line 1
    iget v0, p0, Lg11/e;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ll11/a;->c(Lj11/a;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final f()Lj11/a;
    .locals 1

    .line 1
    iget v0, p0, Lg11/e;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg11/e;->b:Lj11/a;

    .line 7
    .line 8
    check-cast p0, Lj11/z;

    .line 9
    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lg11/e;->b:Lj11/a;

    .line 12
    .line 13
    check-cast p0, Lj11/f;

    .line 14
    .line 15
    return-object p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public g()Z
    .locals 1

    .line 1
    iget v0, p0, Lg11/e;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ll11/a;->g()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final i(Lg11/g;)Lc9/h;
    .locals 0

    .line 1
    iget p0, p0, Lg11/e;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return-object p0

    .line 8
    :pswitch_0
    iget p0, p1, Lg11/g;->c:I

    .line 9
    .line 10
    invoke-static {p0}, Lc9/h;->a(I)Lc9/h;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
