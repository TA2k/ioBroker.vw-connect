.class public final Ll2/e0;
.super Ll2/s1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic b:I

.field public final c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lay0/a;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ll2/e0;->b:I

    sget-object v0, Ll2/x0;->i:Ll2/x0;

    .line 1
    invoke-direct {p0, p1}, Ll2/s1;-><init>(Lay0/a;)V

    .line 2
    iput-object v0, p0, Ll2/e0;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lay0/k;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Ll2/e0;->b:I

    .line 3
    new-instance v0, Ljv0/c;

    const/16 v1, 0x1b

    invoke-direct {v0, v1}, Ljv0/c;-><init>(I)V

    .line 4
    invoke-direct {p0, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 5
    new-instance v0, Ll2/f0;

    invoke-direct {v0, p1}, Ll2/f0;-><init>(Lay0/k;)V

    iput-object v0, p0, Ll2/e0;->c:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)Ll2/t1;
    .locals 8

    .line 1
    iget v0, p0, Ll2/e0;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Ll2/t1;

    .line 7
    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    :goto_0
    move v4, v0

    .line 12
    goto :goto_1

    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    goto :goto_0

    .line 15
    :goto_1
    iget-object v0, p0, Ll2/e0;->c:Ljava/lang/Object;

    .line 16
    .line 17
    move-object v5, v0

    .line 18
    check-cast v5, Ll2/n2;

    .line 19
    .line 20
    const/4 v6, 0x1

    .line 21
    move-object v2, p0

    .line 22
    move-object v3, p1

    .line 23
    invoke-direct/range {v1 .. v6}, Ll2/t1;-><init>(Ll2/s1;Ljava/lang/Object;ZLl2/n2;Z)V

    .line 24
    .line 25
    .line 26
    return-object v1

    .line 27
    :pswitch_0
    move-object v2, p0

    .line 28
    move-object v3, p1

    .line 29
    new-instance p0, Ll2/t1;

    .line 30
    .line 31
    if-nez v3, :cond_1

    .line 32
    .line 33
    const/4 p1, 0x1

    .line 34
    :goto_2
    move v5, p1

    .line 35
    goto :goto_3

    .line 36
    :cond_1
    const/4 p1, 0x0

    .line 37
    goto :goto_2

    .line 38
    :goto_3
    const/4 v6, 0x0

    .line 39
    const/4 v7, 0x1

    .line 40
    move-object v4, v3

    .line 41
    move-object v3, v2

    .line 42
    move-object v2, p0

    .line 43
    invoke-direct/range {v2 .. v7}, Ll2/t1;-><init>(Ll2/s1;Ljava/lang/Object;ZLl2/n2;Z)V

    .line 44
    .line 45
    .line 46
    return-object v2

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public b()Ll2/w2;
    .locals 1

    .line 1
    iget v0, p0, Ll2/e0;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ll2/s1;->b()Ll2/w2;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Ll2/e0;->c:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Ll2/f0;

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
