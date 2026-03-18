.class public final Lk1/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk1/g;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lk1/c;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static final b(ILjava/lang/String;)Lk1/b;
    .locals 1

    .line 1
    sget-object v0, Lk1/r1;->v:Ljava/util/WeakHashMap;

    .line 2
    .line 3
    new-instance v0, Lk1/b;

    .line 4
    .line 5
    invoke-direct {v0, p0, p1}, Lk1/b;-><init>(ILjava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public static final d(ILjava/lang/String;)Lk1/o1;
    .locals 2

    .line 1
    sget-object p0, Lk1/r1;->v:Ljava/util/WeakHashMap;

    .line 2
    .line 3
    new-instance p0, Lk1/o1;

    .line 4
    .line 5
    new-instance v0, Lk1/p0;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v0, v1, v1, v1, v1}, Lk1/p0;-><init>(IIII)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, v0, p1}, Lk1/o1;-><init>(Lk1/p0;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public static e(Ll2/o;)Lk1/r1;
    .locals 4

    .line 1
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->f:Ll2/u2;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Landroid/view/View;

    .line 10
    .line 11
    sget-object v1, Lk1/r1;->v:Ljava/util/WeakHashMap;

    .line 12
    .line 13
    monitor-enter v1

    .line 14
    :try_start_0
    invoke-virtual {v1, v0}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    if-nez v2, :cond_0

    .line 19
    .line 20
    new-instance v2, Lk1/r1;

    .line 21
    .line 22
    invoke-direct {v2, v0}, Lk1/r1;-><init>(Landroid/view/View;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catchall_0
    move-exception p0

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    :goto_0
    check-cast v2, Lk1/r1;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    .line 33
    monitor-exit v1

    .line 34
    invoke-virtual {p0, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    invoke-virtual {p0, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    or-int/2addr v1, v3

    .line 43
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    if-nez v1, :cond_1

    .line 48
    .line 49
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 50
    .line 51
    if-ne v3, v1, :cond_2

    .line 52
    .line 53
    :cond_1
    new-instance v3, Li40/j0;

    .line 54
    .line 55
    const/16 v1, 0x19

    .line 56
    .line 57
    invoke-direct {v3, v1, v2, v0}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    :cond_2
    check-cast v3, Lay0/k;

    .line 64
    .line 65
    invoke-static {v2, v3, p0}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 66
    .line 67
    .line 68
    return-object v2

    .line 69
    :goto_1
    monitor-exit v1

    .line 70
    throw p0
.end method


# virtual methods
.method public c(Lt4/c;I[ILt4/m;[I)V
    .locals 0

    .line 1
    iget p0, p0, Lk1/c;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lt4/m;->d:Lt4/m;

    .line 7
    .line 8
    if-ne p4, p0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    invoke-static {p3, p5, p0}, Lk1/j;->b([I[IZ)V

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 p0, 0x1

    .line 16
    invoke-static {p2, p3, p5, p0}, Lk1/j;->c(I[I[IZ)V

    .line 17
    .line 18
    .line 19
    :goto_0
    return-void

    .line 20
    :pswitch_0
    sget-object p0, Lt4/m;->d:Lt4/m;

    .line 21
    .line 22
    if-ne p4, p0, :cond_1

    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    invoke-static {p2, p3, p5, p0}, Lk1/j;->c(I[I[IZ)V

    .line 26
    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    const/4 p0, 0x1

    .line 30
    invoke-static {p3, p5, p0}, Lk1/j;->b([I[IZ)V

    .line 31
    .line 32
    .line 33
    :goto_1
    return-void

    .line 34
    :pswitch_1
    const/4 p0, 0x0

    .line 35
    invoke-static {p2, p3, p5, p0}, Lk1/j;->c(I[I[IZ)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :pswitch_2
    const/4 p0, 0x0

    .line 40
    invoke-static {p3, p5, p0}, Lk1/j;->b([I[IZ)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lk1/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    const-string p0, "Arrangement#Start"

    .line 12
    .line 13
    return-object p0

    .line 14
    :pswitch_1
    const-string p0, "Arrangement#End"

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_2
    const-string p0, "AbsoluteArrangement#Right"

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_3
    const-string p0, "AbsoluteArrangement#Left"

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
