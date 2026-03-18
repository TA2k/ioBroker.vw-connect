.class public final synthetic Lid/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxb/a;


# direct methods
.method public synthetic constructor <init>(Lxb/a;I)V
    .locals 0

    .line 1
    iput p2, p0, Lid/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lid/a;->e:Lxb/a;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lid/a;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/String;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "it"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-static {}, Ljp/hf;->a()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iget-object p0, p0, Lid/a;->e:Lxb/a;

    .line 22
    .line 23
    iget-object p0, p0, Lxb/a;->a:Lxb/b;

    .line 24
    .line 25
    invoke-interface {p0, p1, v0}, Lxb/b;->a(Ljava/lang/String;Ljava/lang/Integer;)Lretrofit2/Call;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-interface {p0}, Lretrofit2/Call;->request()Ld01/k0;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string p1, "request(...)"

    .line 34
    .line 35
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-static {p0}, Lkc/d;->f(Ld01/k0;)Lkc/e;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :pswitch_0
    const-string v0, "imageId"

    .line 44
    .line 45
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-static {}, Ljp/hf;->a()I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    iget-object p0, p0, Lid/a;->e:Lxb/a;

    .line 57
    .line 58
    iget-object p0, p0, Lxb/a;->a:Lxb/b;

    .line 59
    .line 60
    invoke-interface {p0, p1, v0}, Lxb/b;->a(Ljava/lang/String;Ljava/lang/Integer;)Lretrofit2/Call;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-interface {p0}, Lretrofit2/Call;->request()Ld01/k0;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    const-string p1, "request(...)"

    .line 69
    .line 70
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-static {p0}, Lkc/d;->f(Ld01/k0;)Lkc/e;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
