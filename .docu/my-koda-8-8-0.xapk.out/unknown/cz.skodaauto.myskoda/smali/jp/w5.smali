.class public final Ljp/w5;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/d;


# static fields
.field public static final a:Ljp/w5;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ljp/w5;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ljp/w5;->a:Ljp/w5;

    .line 7
    .line 8
    new-instance v0, Ljp/i0;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, v1}, Ljp/i0;-><init>(I)V

    .line 12
    .line 13
    .line 14
    const-class v1, Ljp/l0;

    .line 15
    .line 16
    invoke-static {v1, v0}, Lia/b;->k(Ljava/lang/Class;Ljp/i0;)Ljava/util/HashMap;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-static {v0, v2}, Lia/b;->m(Ljava/util/HashMap;I)Ljp/i0;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-static {v1, v0}, Lia/b;->k(Ljava/lang/Class;Ljp/i0;)Ljava/util/HashMap;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const/4 v2, 0x3

    .line 30
    invoke-static {v0, v2}, Lia/b;->m(Ljava/util/HashMap;I)Ljp/i0;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-static {v1, v0}, Lia/b;->k(Ljava/lang/Class;Ljp/i0;)Ljava/util/HashMap;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    const/4 v2, 0x4

    .line 39
    invoke-static {v0, v2}, Lia/b;->m(Ljava/util/HashMap;I)Ljp/i0;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-static {v1, v0}, Lia/b;->k(Ljava/lang/Class;Ljp/i0;)Ljava/util/HashMap;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    const/4 v2, 0x5

    .line 48
    invoke-static {v0, v2}, Lia/b;->m(Ljava/util/HashMap;I)Ljp/i0;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    invoke-static {v1, v0}, Lia/b;->k(Ljava/lang/Class;Ljp/i0;)Ljava/util/HashMap;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    const/4 v2, 0x6

    .line 57
    invoke-static {v0, v2}, Lia/b;->m(Ljava/util/HashMap;I)Ljp/i0;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    invoke-static {v1, v0}, Lia/b;->k(Ljava/lang/Class;Ljp/i0;)Ljava/util/HashMap;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    const/4 v2, 0x7

    .line 66
    invoke-static {v0, v2}, Lia/b;->m(Ljava/util/HashMap;I)Ljp/i0;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    invoke-static {v1, v0}, Lia/b;->k(Ljava/lang/Class;Ljp/i0;)Ljava/util/HashMap;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    invoke-static {v0}, Lia/b;->u(Ljava/util/HashMap;)V

    .line 75
    .line 76
    .line 77
    return-void
.end method


# virtual methods
.method public final synthetic a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    check-cast p2, Lzs/e;

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    throw p0

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/ClassCastException;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 10
    .line 11
    .line 12
    throw p0
.end method
