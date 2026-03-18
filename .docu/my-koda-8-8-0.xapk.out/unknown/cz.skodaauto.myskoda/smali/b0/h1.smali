.class public final Lb0/h1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/n2;
.implements Lb0/z;


# instance fields
.field public final synthetic a:I

.field public final b:Lh0/j1;


# direct methods
.method public constructor <init>(I)V
    .locals 0

    iput p1, p0, Lb0/h1;->a:I

    packed-switch p1, :pswitch_data_0

    .line 1
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    move-result-object p1

    invoke-direct {p0, p1}, Lb0/h1;-><init>(Lh0/j1;)V

    return-void

    .line 2
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    move-result-object p1

    iput-object p1, p0, Lb0/h1;->b:Lh0/j1;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Lh0/j1;)V
    .locals 5

    const/4 v0, 0x0

    iput v0, p0, Lb0/h1;->a:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Lb0/h1;->b:Lh0/j1;

    .line 6
    sget-object v0, Ll0/k;->h1:Lh0/g;

    const/4 v1, 0x0

    .line 7
    invoke-virtual {p1, v0, v1}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Class;

    .line 8
    const-class v3, Lb0/k1;

    if-eqz v2, :cond_1

    invoke-virtual {v2, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    goto :goto_0

    .line 9
    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Invalid target class configuration for "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, ": "

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 10
    :cond_1
    :goto_0
    sget-object p0, Lh0/q2;->e:Lh0/q2;

    .line 11
    sget-object v2, Lh0/o2;->Z0:Lh0/g;

    invoke-virtual {p1, v2, p0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 12
    invoke-virtual {p1, v0, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 13
    sget-object p0, Ll0/k;->g1:Lh0/g;

    invoke-virtual {p1, p0, v1}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_2

    .line 14
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "-"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 15
    invoke-virtual {p1, p0, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 16
    :cond_2
    sget-object p0, Lh0/a1;->I0:Lh0/g;

    const/4 v0, -0x1

    .line 17
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    .line 18
    invoke-virtual {p1, p0, v1}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v1

    if-ne v1, v0, :cond_3

    const/4 v0, 0x2

    .line 19
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-virtual {p1, p0, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    :cond_3
    return-void
.end method


# virtual methods
.method public final a()Lh0/i1;
    .locals 1

    .line 1
    iget v0, p0, Lb0/h1;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    throw p0

    .line 8
    :pswitch_0
    iget-object p0, p0, Lb0/h1;->b:Lh0/j1;

    .line 9
    .line 10
    return-object p0

    .line 11
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public b()Lh0/o2;
    .locals 1

    .line 1
    new-instance v0, Lh0/o1;

    .line 2
    .line 3
    iget-object p0, p0, Lb0/h1;->b:Lh0/j1;

    .line 4
    .line 5
    invoke-static {p0}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-direct {v0, p0}, Lh0/o1;-><init>(Lh0/n1;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public c()Lb0/k1;
    .locals 1

    .line 1
    new-instance v0, Lh0/o1;

    .line 2
    .line 3
    iget-object p0, p0, Lb0/h1;->b:Lh0/j1;

    .line 4
    .line 5
    invoke-static {p0}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-direct {v0, p0}, Lh0/o1;-><init>(Lh0/n1;)V

    .line 10
    .line 11
    .line 12
    invoke-static {v0}, Lh0/a1;->L(Lh0/a1;)V

    .line 13
    .line 14
    .line 15
    new-instance p0, Lb0/k1;

    .line 16
    .line 17
    invoke-direct {p0, v0}, Lb0/z1;-><init>(Lh0/o2;)V

    .line 18
    .line 19
    .line 20
    sget-object v0, Lb0/k1;->x:Lj0/c;

    .line 21
    .line 22
    iput-object v0, p0, Lb0/k1;->q:Ljava/util/concurrent/Executor;

    .line 23
    .line 24
    return-object p0
.end method

.method public d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V
    .locals 1

    .line 1
    invoke-static {p1}, Lt/a;->X(Landroid/hardware/camera2/CaptureRequest$Key;)Lh0/g;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-object p0, p0, Lb0/h1;->b:Lh0/j1;

    .line 6
    .line 7
    sget-object v0, Lh0/p0;->f:Lh0/p0;

    .line 8
    .line 9
    invoke-virtual {p0, p1, v0, p2}, Lh0/j1;->m(Lh0/g;Lh0/p0;Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method
