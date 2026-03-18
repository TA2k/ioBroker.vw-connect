.class public final Ljb/c;
.super Ljb/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic b:I

.field public final c:I


# direct methods
.method public constructor <init>(Lh2/s;I)V
    .locals 0

    iput p2, p0, Ljb/c;->b:I

    packed-switch p2, :pswitch_data_0

    const-string p2, "tracker"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0, p1}, Ljb/b;-><init>(Lh2/s;)V

    const/4 p1, 0x6

    .line 2
    iput p1, p0, Ljb/c;->c:I

    return-void

    .line 3
    :pswitch_0
    const-string p2, "tracker"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-direct {p0, p1}, Ljb/b;-><init>(Lh2/s;)V

    const/16 p1, 0x9

    .line 5
    iput p1, p0, Ljb/c;->c:I

    return-void

    .line 6
    :pswitch_1
    const-string p2, "tracker"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    invoke-direct {p0, p1}, Ljb/b;-><init>(Lh2/s;)V

    const/4 p1, 0x7

    .line 8
    iput p1, p0, Ljb/c;->c:I

    return-void

    .line 9
    :pswitch_2
    const-string p2, "tracker"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    invoke-direct {p0, p1}, Ljb/b;-><init>(Lh2/s;)V

    const/4 p1, 0x7

    .line 11
    iput p1, p0, Ljb/c;->c:I

    return-void

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Lkb/a;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ljb/c;->b:I

    const-string v0, "tracker"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    invoke-direct {p0, p1}, Ljb/b;-><init>(Lh2/s;)V

    const/4 p1, 0x5

    .line 13
    iput p1, p0, Ljb/c;->c:I

    return-void
.end method


# virtual methods
.method public final b(Lmb/o;)Z
    .locals 1

    .line 1
    iget p0, p0, Ljb/c;->b:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "workSpec"

    .line 7
    .line 8
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p1, Lmb/o;->j:Leb/e;

    .line 12
    .line 13
    iget-boolean p0, p0, Leb/e;->f:Z

    .line 14
    .line 15
    return p0

    .line 16
    :pswitch_0
    const-string p0, "workSpec"

    .line 17
    .line 18
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p1, Lmb/o;->j:Leb/e;

    .line 22
    .line 23
    iget-object p0, p0, Leb/e;->a:Leb/x;

    .line 24
    .line 25
    sget-object p1, Leb/x;->f:Leb/x;

    .line 26
    .line 27
    if-eq p0, p1, :cond_1

    .line 28
    .line 29
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 30
    .line 31
    const/16 v0, 0x1e

    .line 32
    .line 33
    if-lt p1, v0, :cond_0

    .line 34
    .line 35
    sget-object p1, Leb/x;->i:Leb/x;

    .line 36
    .line 37
    if-ne p0, p1, :cond_0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    const/4 p0, 0x0

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 43
    :goto_1
    return p0

    .line 44
    :pswitch_1
    const-string p0, "workSpec"

    .line 45
    .line 46
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    iget-object p0, p1, Lmb/o;->j:Leb/e;

    .line 50
    .line 51
    iget-object p0, p0, Leb/e;->a:Leb/x;

    .line 52
    .line 53
    sget-object p1, Leb/x;->e:Leb/x;

    .line 54
    .line 55
    if-ne p0, p1, :cond_2

    .line 56
    .line 57
    const/4 p0, 0x1

    .line 58
    goto :goto_2

    .line 59
    :cond_2
    const/4 p0, 0x0

    .line 60
    :goto_2
    return p0

    .line 61
    :pswitch_2
    const-string p0, "workSpec"

    .line 62
    .line 63
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    iget-object p0, p1, Lmb/o;->j:Leb/e;

    .line 67
    .line 68
    iget-boolean p0, p0, Leb/e;->e:Z

    .line 69
    .line 70
    return p0

    .line 71
    :pswitch_3
    const-string p0, "workSpec"

    .line 72
    .line 73
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    iget-object p0, p1, Lmb/o;->j:Leb/e;

    .line 77
    .line 78
    iget-boolean p0, p0, Leb/e;->c:Z

    .line 79
    .line 80
    return p0

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final c()I
    .locals 1

    .line 1
    iget v0, p0, Ljb/c;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p0, Ljb/c;->c:I

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_0
    iget p0, p0, Ljb/c;->c:I

    .line 10
    .line 11
    return p0

    .line 12
    :pswitch_1
    iget p0, p0, Ljb/c;->c:I

    .line 13
    .line 14
    return p0

    .line 15
    :pswitch_2
    iget p0, p0, Ljb/c;->c:I

    .line 16
    .line 17
    return p0

    .line 18
    :pswitch_3
    iget p0, p0, Ljb/c;->c:I

    .line 19
    .line 20
    return p0

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget p0, p0, Ljb/c;->b:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    :goto_0
    xor-int/lit8 p0, p0, 0x1

    .line 13
    .line 14
    return p0

    .line 15
    :pswitch_0
    check-cast p1, Lib/e;

    .line 16
    .line 17
    const-string p0, "value"

    .line 18
    .line 19
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-boolean p0, p1, Lib/e;->a:Z

    .line 23
    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    iget-boolean p0, p1, Lib/e;->c:Z

    .line 27
    .line 28
    if-eqz p0, :cond_0

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_0
    const/4 p0, 0x0

    .line 32
    goto :goto_2

    .line 33
    :cond_1
    :goto_1
    const/4 p0, 0x1

    .line 34
    :goto_2
    return p0

    .line 35
    :pswitch_1
    check-cast p1, Lib/e;

    .line 36
    .line 37
    const-string p0, "value"

    .line 38
    .line 39
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    iget-boolean p0, p1, Lib/e;->a:Z

    .line 43
    .line 44
    if-eqz p0, :cond_3

    .line 45
    .line 46
    iget-boolean p0, p1, Lib/e;->b:Z

    .line 47
    .line 48
    if-nez p0, :cond_2

    .line 49
    .line 50
    goto :goto_3

    .line 51
    :cond_2
    const/4 p0, 0x0

    .line 52
    goto :goto_4

    .line 53
    :cond_3
    :goto_3
    const/4 p0, 0x1

    .line 54
    :goto_4
    return p0

    .line 55
    :pswitch_2
    check-cast p1, Ljava/lang/Boolean;

    .line 56
    .line 57
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    goto :goto_0

    .line 62
    :pswitch_3
    check-cast p1, Ljava/lang/Boolean;

    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    goto :goto_0

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
