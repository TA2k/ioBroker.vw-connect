.class public final Lwz0/b;
.super Llp/v0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lwz0/s;

.field public final synthetic c:Ljava/lang/String;

.field public final d:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lwz0/s;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lwz0/b;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lwz0/b;->b:Lwz0/s;

    iput-object p2, p0, Lwz0/b;->c:Ljava/lang/String;

    .line 3
    iget-object p1, p1, Lwz0/s;->b:Lvz0/d;

    .line 4
    iget-object p1, p1, Lvz0/d;->b:Lwq/f;

    .line 5
    iput-object p1, p0, Lwz0/b;->d:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lwz0/s;Ljava/lang/String;Lsz0/g;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lwz0/b;->a:I

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput-object p1, p0, Lwz0/b;->b:Lwz0/s;

    iput-object p2, p0, Lwz0/b;->c:Ljava/lang/String;

    iput-object p3, p0, Lwz0/b;->d:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public B(I)V
    .locals 1

    .line 1
    iget v0, p0, Lwz0/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Llp/v0;->B(I)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    invoke-static {p1}, Ljava/lang/Integer;->toUnsignedString(I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-virtual {p0, p1}, Lwz0/b;->I(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public E(Ljava/lang/String;)V
    .locals 3

    .line 1
    iget v0, p0, Lwz0/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Llp/v0;->E(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    const-string v0, "value"

    .line 11
    .line 12
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v0, Lvz0/u;

    .line 16
    .line 17
    iget-object v1, p0, Lwz0/b;->d:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lsz0/g;

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    invoke-direct {v0, p1, v2, v1}, Lvz0/u;-><init>(Ljava/lang/Object;ZLsz0/g;)V

    .line 23
    .line 24
    .line 25
    iget-object p1, p0, Lwz0/b;->b:Lwz0/s;

    .line 26
    .line 27
    iget-object p0, p0, Lwz0/b;->c:Ljava/lang/String;

    .line 28
    .line 29
    invoke-virtual {p1, p0, v0}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public I(Ljava/lang/String;)V
    .locals 3

    .line 1
    const-string v0, "s"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lvz0/u;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x0

    .line 10
    invoke-direct {v0, p1, v1, v2}, Lvz0/u;-><init>(Ljava/lang/Object;ZLsz0/g;)V

    .line 11
    .line 12
    .line 13
    iget-object p1, p0, Lwz0/b;->b:Lwz0/s;

    .line 14
    .line 15
    iget-object p0, p0, Lwz0/b;->c:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {p1, p0, v0}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final c()Lwq/f;
    .locals 1

    .line 1
    iget v0, p0, Lwz0/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lwz0/b;->d:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lwq/f;

    .line 9
    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lwz0/b;->b:Lwz0/s;

    .line 12
    .line 13
    iget-object p0, p0, Lwz0/s;->b:Lvz0/d;

    .line 14
    .line 15
    iget-object p0, p0, Lvz0/d;->b:Lwq/f;

    .line 16
    .line 17
    return-object p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public f(B)V
    .locals 1

    .line 1
    iget v0, p0, Lwz0/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Llp/v0;->f(B)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    invoke-static {p1}, Llx0/s;->a(B)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-virtual {p0, p1}, Lwz0/b;->I(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public m(J)V
    .locals 1

    .line 1
    iget v0, p0, Lwz0/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Llp/v0;->m(J)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    invoke-static {p1, p2}, Ljava/lang/Long;->toUnsignedString(J)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-virtual {p0, p1}, Lwz0/b;->I(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public r(S)V
    .locals 1

    .line 1
    iget v0, p0, Lwz0/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Llp/v0;->r(S)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    invoke-static {p1}, Llx0/z;->a(S)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-virtual {p0, p1}, Lwz0/b;->I(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
