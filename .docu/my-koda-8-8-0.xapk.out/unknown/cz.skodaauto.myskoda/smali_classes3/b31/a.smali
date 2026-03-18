.class public final Lb31/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Lyy0/j1;


# direct methods
.method public constructor <init>(I)V
    .locals 0

    iput p1, p0, Lb31/a;->a:I

    packed-switch p1, :pswitch_data_0

    const/4 p1, 0x0

    .line 3
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Lb31/a;->b:Lyy0/j1;

    return-void

    :pswitch_0
    const/4 p1, 0x0

    .line 6
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-object p1, p0, Lb31/a;->b:Lyy0/j1;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Lyy0/c2;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lb31/a;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lb31/a;->b:Lyy0/j1;

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 3

    .line 1
    iget v0, p0, Lb31/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v0, p1

    .line 7
    check-cast v0, Li31/j;

    .line 8
    .line 9
    iget-object p0, p0, Lb31/a;->b:Lyy0/j1;

    .line 10
    .line 11
    move-object v1, p0

    .line 12
    check-cast v1, Lyy0/c2;

    .line 13
    .line 14
    :cond_0
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    move-object p1, p0

    .line 19
    check-cast p1, Li31/j;

    .line 20
    .line 21
    invoke-virtual {v1, p0, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    return-void

    .line 28
    :pswitch_0
    move-object v0, p1

    .line 29
    check-cast v0, Li31/d0;

    .line 30
    .line 31
    :cond_1
    iget-object p1, p0, Lb31/a;->b:Lyy0/j1;

    .line 32
    .line 33
    check-cast p1, Lyy0/c2;

    .line 34
    .line 35
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    move-object v2, v1

    .line 40
    check-cast v2, Li31/d0;

    .line 41
    .line 42
    invoke-virtual {p1, v1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    if-eqz p1, :cond_1

    .line 47
    .line 48
    return-void

    .line 49
    :pswitch_1
    check-cast p1, Li31/b;

    .line 50
    .line 51
    :cond_2
    iget-object v0, p0, Lb31/a;->b:Lyy0/j1;

    .line 52
    .line 53
    check-cast v0, Lyy0/c2;

    .line 54
    .line 55
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    move-object v2, v1

    .line 60
    check-cast v2, Li31/b;

    .line 61
    .line 62
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-eqz v0, :cond_2

    .line 67
    .line 68
    return-void

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b()V
    .locals 3

    .line 1
    iget v0, p0, Lb31/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lb31/a;->b:Lyy0/j1;

    .line 7
    .line 8
    move-object v0, p0

    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    :cond_0
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    move-object v1, p0

    .line 16
    check-cast v1, Li31/j;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    invoke-virtual {v0, p0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    return-void

    .line 26
    :cond_1
    :pswitch_0
    iget-object v0, p0, Lb31/a;->b:Lyy0/j1;

    .line 27
    .line 28
    check-cast v0, Lyy0/c2;

    .line 29
    .line 30
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    move-object v2, v1

    .line 35
    check-cast v2, Li31/d0;

    .line 36
    .line 37
    const/4 v2, 0x0

    .line 38
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_1

    .line 43
    .line 44
    return-void

    .line 45
    :cond_2
    :pswitch_1
    iget-object v0, p0, Lb31/a;->b:Lyy0/j1;

    .line 46
    .line 47
    check-cast v0, Lyy0/c2;

    .line 48
    .line 49
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    move-object v2, v1

    .line 54
    check-cast v2, Li31/b;

    .line 55
    .line 56
    const/4 v2, 0x0

    .line 57
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-eqz v0, :cond_2

    .line 62
    .line 63
    return-void

    .line 64
    nop

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final c()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lb31/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lb31/a;->b:Lyy0/j1;

    .line 7
    .line 8
    check-cast p0, Lyy0/c2;

    .line 9
    .line 10
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Li31/j;

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_0
    iget-object p0, p0, Lb31/a;->b:Lyy0/j1;

    .line 18
    .line 19
    check-cast p0, Lyy0/c2;

    .line 20
    .line 21
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Li31/d0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_1
    iget-object p0, p0, Lb31/a;->b:Lyy0/j1;

    .line 29
    .line 30
    check-cast p0, Lyy0/c2;

    .line 31
    .line 32
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Li31/b;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Lay0/k;)V
    .locals 3

    .line 1
    iget v0, p0, Lb31/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lb31/a;->b:Lyy0/j1;

    .line 7
    .line 8
    move-object v0, p0

    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    :cond_0
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    move-object v1, p0

    .line 16
    check-cast v1, Li31/j;

    .line 17
    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    invoke-interface {p1, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    check-cast v1, Li31/j;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    const/4 v1, 0x0

    .line 28
    :goto_0
    invoke-virtual {v0, p0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eqz p0, :cond_0

    .line 33
    .line 34
    return-void

    .line 35
    :cond_2
    :pswitch_0
    iget-object v0, p0, Lb31/a;->b:Lyy0/j1;

    .line 36
    .line 37
    check-cast v0, Lyy0/c2;

    .line 38
    .line 39
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    move-object v2, v1

    .line 44
    check-cast v2, Li31/d0;

    .line 45
    .line 46
    if-eqz v2, :cond_3

    .line 47
    .line 48
    invoke-interface {p1, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    check-cast v2, Li31/d0;

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    const/4 v2, 0x0

    .line 56
    :goto_1
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-eqz v0, :cond_2

    .line 61
    .line 62
    return-void

    .line 63
    :cond_4
    :pswitch_1
    iget-object v0, p0, Lb31/a;->b:Lyy0/j1;

    .line 64
    .line 65
    check-cast v0, Lyy0/c2;

    .line 66
    .line 67
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    move-object v2, v1

    .line 72
    check-cast v2, Li31/b;

    .line 73
    .line 74
    if-eqz v2, :cond_5

    .line 75
    .line 76
    invoke-interface {p1, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    check-cast v2, Li31/b;

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_5
    const/4 v2, 0x0

    .line 84
    :goto_2
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v0

    .line 88
    if-eqz v0, :cond_4

    .line 89
    .line 90
    return-void

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
