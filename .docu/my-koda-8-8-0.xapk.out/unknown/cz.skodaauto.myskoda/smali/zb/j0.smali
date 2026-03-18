.class public final synthetic Lzb/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lzb/g;

.field public final synthetic f:Ll2/t2;


# direct methods
.method public synthetic constructor <init>(Lzb/g;Ll2/t2;I)V
    .locals 0

    .line 1
    iput p3, p0, Lzb/j0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lzb/j0;->e:Lzb/g;

    .line 4
    .line 5
    iput-object p2, p0, Lzb/j0;->f:Ll2/t2;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lzb/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lhi/a;

    .line 7
    .line 8
    const-string v0, "$this$single"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance p1, Lzb/h;

    .line 14
    .line 15
    iget-object v0, p0, Lzb/j0;->e:Lzb/g;

    .line 16
    .line 17
    iget-object p0, p0, Lzb/j0;->f:Ll2/t2;

    .line 18
    .line 19
    invoke-direct {p1, v0, p0}, Lzb/h;-><init>(Lzb/g;Ll2/t2;)V

    .line 20
    .line 21
    .line 22
    return-object p1

    .line 23
    :pswitch_0
    check-cast p1, Lhi/c;

    .line 24
    .line 25
    const-string v0, "$this$module"

    .line 26
    .line 27
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    new-instance v0, Lzb/j0;

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    iget-object v2, p0, Lzb/j0;->e:Lzb/g;

    .line 34
    .line 35
    iget-object p0, p0, Lzb/j0;->f:Ll2/t2;

    .line 36
    .line 37
    invoke-direct {v0, v2, p0, v1}, Lzb/j0;-><init>(Lzb/g;Ll2/t2;I)V

    .line 38
    .line 39
    .line 40
    new-instance p0, Lii/b;

    .line 41
    .line 42
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 43
    .line 44
    const-class v2, Lzb/h;

    .line 45
    .line 46
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    const/4 v3, 0x0

    .line 51
    invoke-direct {p0, v3, v0, v2}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 52
    .line 53
    .line 54
    iget-object p1, p1, Lhi/c;->a:Ljava/util/ArrayList;

    .line 55
    .line 56
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    new-instance p0, Lz70/e0;

    .line 60
    .line 61
    const/16 v0, 0xa

    .line 62
    .line 63
    invoke-direct {p0, v0}, Lz70/e0;-><init>(I)V

    .line 64
    .line 65
    .line 66
    new-instance v0, Lii/b;

    .line 67
    .line 68
    const-class v2, Loc/d;

    .line 69
    .line 70
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    invoke-direct {v0, v3, p0, v2}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    new-instance p0, Lz70/e0;

    .line 81
    .line 82
    const/16 v0, 0xb

    .line 83
    .line 84
    invoke-direct {p0, v0}, Lz70/e0;-><init>(I)V

    .line 85
    .line 86
    .line 87
    new-instance v0, Lii/b;

    .line 88
    .line 89
    const-class v2, Lec/c;

    .line 90
    .line 91
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    invoke-direct {v0, v3, p0, v1}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    return-object p0

    .line 104
    nop

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
