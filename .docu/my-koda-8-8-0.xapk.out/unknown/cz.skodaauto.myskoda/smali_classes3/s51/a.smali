.class public abstract Ls51/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lvw0/a;

.field public static final b:Lvw0/a;

.field public static final c:Lvw0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 2
    .line 3
    const-class v1, Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v2, 0x0

    .line 10
    :try_start_0
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 11
    .line 12
    .line 13
    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    goto :goto_0

    .line 15
    :catchall_0
    move-object v3, v2

    .line 16
    :goto_0
    new-instance v4, Lzw0/a;

    .line 17
    .line 18
    invoke-direct {v4, v0, v3}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 19
    .line 20
    .line 21
    new-instance v0, Lvw0/a;

    .line 22
    .line 23
    const-string v3, "cat-unique-request-identifier"

    .line 24
    .line 25
    invoke-direct {v0, v3, v4}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 26
    .line 27
    .line 28
    sput-object v0, Ls51/a;->a:Lvw0/a;

    .line 29
    .line 30
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    :try_start_1
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 37
    .line 38
    .line 39
    move-result-object v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 40
    goto :goto_1

    .line 41
    :catchall_1
    move-object v1, v2

    .line 42
    :goto_1
    new-instance v3, Lzw0/a;

    .line 43
    .line 44
    invoke-direct {v3, v0, v1}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 45
    .line 46
    .line 47
    new-instance v0, Lvw0/a;

    .line 48
    .line 49
    const-string v1, "cat-request-uuid"

    .line 50
    .line 51
    invoke-direct {v0, v1, v3}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 52
    .line 53
    .line 54
    sput-object v0, Ls51/a;->b:Lvw0/a;

    .line 55
    .line 56
    const-class v0, Ljava/lang/Boolean;

    .line 57
    .line 58
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 59
    .line 60
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    :try_start_2
    sget-object v1, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 65
    .line 66
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 67
    .line 68
    .line 69
    :catchall_2
    const-string v1, "type"

    .line 70
    .line 71
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    const-string v0, "cat-request-contains-sensitive-information"

    .line 75
    .line 76
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-nez v0, :cond_0

    .line 81
    .line 82
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 83
    .line 84
    const-class v1, Ljava/util/Set;

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    :try_start_3
    sget-object v3, Lhy0/d0;->c:Lhy0/d0;

    .line 91
    .line 92
    const-class v3, Low0/v;

    .line 93
    .line 94
    invoke-static {v3}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    invoke-static {v3}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 99
    .line 100
    .line 101
    move-result-object v3

    .line 102
    invoke-static {v1, v3}, Lkotlin/jvm/internal/g0;->c(Ljava/lang/Class;Lhy0/d0;)Lhy0/a0;

    .line 103
    .line 104
    .line 105
    move-result-object v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 106
    :catchall_3
    new-instance v1, Lzw0/a;

    .line 107
    .line 108
    invoke-direct {v1, v0, v2}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 109
    .line 110
    .line 111
    new-instance v0, Lvw0/a;

    .line 112
    .line 113
    const-string v2, "cat-request-accept-http-status-codes"

    .line 114
    .line 115
    invoke-direct {v0, v2, v1}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 116
    .line 117
    .line 118
    sput-object v0, Ls51/a;->c:Lvw0/a;

    .line 119
    .line 120
    return-void

    .line 121
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 122
    .line 123
    const-string v1, "Name can\'t be blank"

    .line 124
    .line 125
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    throw v0
.end method
