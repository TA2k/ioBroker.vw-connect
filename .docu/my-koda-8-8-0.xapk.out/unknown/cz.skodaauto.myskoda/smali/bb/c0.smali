.class public final Lbb/c0;
.super Lbb/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:Lbb/x;


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lbb/c0;->a:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lbb/x;I)V
    .locals 0

    .line 2
    iput p2, p0, Lbb/c0;->a:I

    iput-object p1, p0, Lbb/c0;->b:Lbb/x;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public c(Lbb/x;)V
    .locals 2

    .line 1
    iget v0, p0, Lbb/c0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object v0, p0, Lbb/c0;->b:Lbb/x;

    .line 8
    .line 9
    invoke-virtual {v0}, Lbb/x;->E()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1, p0}, Lbb/x;->B(Lbb/v;)Lbb/x;

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_1
    iget-object v0, p0, Lbb/c0;->b:Lbb/x;

    .line 17
    .line 18
    check-cast v0, Lbb/d0;

    .line 19
    .line 20
    iget v1, v0, Lbb/d0;->J:I

    .line 21
    .line 22
    add-int/lit8 v1, v1, -0x1

    .line 23
    .line 24
    iput v1, v0, Lbb/d0;->J:I

    .line 25
    .line 26
    if-nez v1, :cond_0

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    iput-boolean v1, v0, Lbb/d0;->K:Z

    .line 30
    .line 31
    invoke-virtual {v0}, Lbb/x;->n()V

    .line 32
    .line 33
    .line 34
    :cond_0
    invoke-virtual {p1, p0}, Lbb/x;->B(Lbb/v;)Lbb/x;

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public e(Lbb/x;)V
    .locals 1

    .line 1
    iget v0, p0, Lbb/c0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lbb/c0;->b:Lbb/x;

    .line 8
    .line 9
    check-cast p0, Lbb/d0;

    .line 10
    .line 11
    iget-object v0, p0, Lbb/d0;->H:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Lbb/d0;->t()Z

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    if-nez p1, :cond_0

    .line 21
    .line 22
    sget-object p1, Lbb/w;->j0:Lb8/b;

    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    invoke-virtual {p0, p0, p1, v0}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 26
    .line 27
    .line 28
    const/4 p1, 0x1

    .line 29
    iput-boolean p1, p0, Lbb/x;->u:Z

    .line 30
    .line 31
    sget-object p1, Lbb/w;->i0:Lb8/b;

    .line 32
    .line 33
    invoke-virtual {p0, p0, p1, v0}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 34
    .line 35
    .line 36
    :cond_0
    return-void

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public f(Lbb/x;)V
    .locals 0

    .line 1
    iget p1, p0, Lbb/c0;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lbb/c0;->b:Lbb/x;

    .line 8
    .line 9
    check-cast p0, Lbb/d0;

    .line 10
    .line 11
    iget-boolean p1, p0, Lbb/d0;->K:Z

    .line 12
    .line 13
    if-nez p1, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Lbb/x;->M()V

    .line 16
    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    iput-boolean p1, p0, Lbb/d0;->K:Z

    .line 20
    .line 21
    :cond_0
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
