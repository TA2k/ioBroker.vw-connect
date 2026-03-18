.class public final synthetic Lld/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Lzb/s0;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Lzb/s0;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lld/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lld/a;->e:Ll2/b1;

    iput-object p2, p0, Lld/a;->f:Lzb/s0;

    return-void
.end method

.method public synthetic constructor <init>(Lzb/s0;Ll2/b1;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lld/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lld/a;->f:Lzb/s0;

    iput-object p2, p0, Lld/a;->e:Ll2/b1;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lld/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lb1/n;

    .line 4
    .line 5
    check-cast p2, Lz9/k;

    .line 6
    .line 7
    check-cast p3, Ll2/o;

    .line 8
    .line 9
    check-cast p4, Ljava/lang/Integer;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    const-string v0, "$this$composable"

    .line 15
    .line 16
    const-string v1, "it"

    .line 17
    .line 18
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Lld/a;->e:Ll2/b1;

    .line 22
    .line 23
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    check-cast p1, Lrd/a;

    .line 28
    .line 29
    const/4 p2, 0x0

    .line 30
    check-cast p3, Ll2/t;

    .line 31
    .line 32
    if-nez p1, :cond_0

    .line 33
    .line 34
    const p0, -0x36cda725

    .line 35
    .line 36
    .line 37
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 38
    .line 39
    .line 40
    :goto_0
    invoke-virtual {p3, p2}, Ll2/t;->q(Z)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_0
    const p4, -0x36cda724    # -730509.75f

    .line 45
    .line 46
    .line 47
    invoke-virtual {p3, p4}, Ll2/t;->Y(I)V

    .line 48
    .line 49
    .line 50
    iget-object p0, p0, Lld/a;->f:Lzb/s0;

    .line 51
    .line 52
    invoke-static {p0, p1, p3, p2}, Lkp/u7;->a(Lzb/s0;Lrd/a;Ll2/o;I)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_0
    const-string v0, "$this$composable"

    .line 60
    .line 61
    const-string v1, "it"

    .line 62
    .line 63
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    iget-object p1, p0, Lld/a;->e:Ll2/b1;

    .line 67
    .line 68
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    check-cast p1, Ldd/f;

    .line 73
    .line 74
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    const/4 p2, 0x0

    .line 78
    iget-object p0, p0, Lld/a;->f:Lzb/s0;

    .line 79
    .line 80
    invoke-static {p1, p0, p3, p2}, Ljp/c1;->a(Ldd/f;Lzb/s0;Ll2/o;I)V

    .line 81
    .line 82
    .line 83
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    return-object p0

    .line 86
    nop

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
