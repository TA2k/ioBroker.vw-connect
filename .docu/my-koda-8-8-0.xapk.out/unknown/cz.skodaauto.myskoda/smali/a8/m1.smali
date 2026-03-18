.class public final La8/m1;
.super Lh8/q;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic c:I

.field public final d:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lt7/p0;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, La8/m1;->c:I

    .line 3
    invoke-direct {p0, p1}, Lh8/q;-><init>(Lt7/p0;)V

    .line 4
    new-instance p1, Lt7/o0;

    invoke-direct {p1}, Lt7/o0;-><init>()V

    iput-object p1, p0, La8/m1;->d:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lt7/p0;Lt7/x;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, La8/m1;->c:I

    .line 1
    invoke-direct {p0, p1}, Lh8/q;-><init>(Lt7/p0;)V

    .line 2
    iput-object p2, p0, La8/m1;->d:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public f(ILt7/n0;Z)Lt7/n0;
    .locals 11

    .line 1
    iget v0, p0, La8/m1;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2, p3}, Lh8/q;->f(ILt7/n0;Z)Lt7/n0;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object v0, p0, Lh8/q;->b:Lt7/p0;

    .line 12
    .line 13
    invoke-virtual {v0, p1, p2, p3}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iget p1, v1, Lt7/n0;->c:I

    .line 18
    .line 19
    iget-object p0, p0, La8/m1;->d:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Lt7/o0;

    .line 22
    .line 23
    const-wide/16 v2, 0x0

    .line 24
    .line 25
    invoke-virtual {v0, p1, p0, v2, v3}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {p0}, Lt7/o0;->a()Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-eqz p0, :cond_0

    .line 34
    .line 35
    iget-object v2, p2, Lt7/n0;->a:Ljava/lang/Object;

    .line 36
    .line 37
    iget-object v3, p2, Lt7/n0;->b:Ljava/lang/Object;

    .line 38
    .line 39
    iget v4, p2, Lt7/n0;->c:I

    .line 40
    .line 41
    iget-wide v5, p2, Lt7/n0;->d:J

    .line 42
    .line 43
    iget-wide v7, p2, Lt7/n0;->e:J

    .line 44
    .line 45
    sget-object v9, Lt7/b;->c:Lt7/b;

    .line 46
    .line 47
    const/4 v10, 0x1

    .line 48
    invoke-virtual/range {v1 .. v10}, Lt7/n0;->h(Ljava/lang/Object;Ljava/lang/Object;IJJLt7/b;Z)V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    const/4 p0, 0x1

    .line 53
    iput-boolean p0, v1, Lt7/n0;->f:Z

    .line 54
    .line 55
    :goto_0
    return-object v1

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public m(ILt7/o0;J)Lt7/o0;
    .locals 1

    .line 1
    iget v0, p0, La8/m1;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2, p3, p4}, Lh8/q;->m(ILt7/o0;J)Lt7/o0;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    invoke-super {p0, p1, p2, p3, p4}, Lh8/q;->m(ILt7/o0;J)Lt7/o0;

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, La8/m1;->d:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Lt7/x;

    .line 17
    .line 18
    iput-object p0, p2, Lt7/o0;->c:Lt7/x;

    .line 19
    .line 20
    iget-object p0, p0, Lt7/x;->b:Lt7/u;

    .line 21
    .line 22
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    return-object p2

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
