.class public abstract Lkj0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lly0/n;

.field public static final b:Ljava/util/List;

.field public static final c:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lly0/n;

    .line 2
    .line 3
    const-string v1, "[a-zA-Z][\\w]{0,23}"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lkj0/l;->a:Lly0/n;

    .line 9
    .line 10
    const-string v0, "user_id"

    .line 11
    .line 12
    const-string v1, "first_open_after_install"

    .line 13
    .line 14
    const-string v2, "first_open_time"

    .line 15
    .line 16
    const-string v3, "first_visit_time"

    .line 17
    .line 18
    const-string v4, "last_deep_link_referrer"

    .line 19
    .line 20
    filled-new-array {v2, v3, v4, v0, v1}, [Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    sput-object v0, Lkj0/l;->b:Ljava/util/List;

    .line 29
    .line 30
    const-string v0, "google_"

    .line 31
    .line 32
    const-string v1, "ga_"

    .line 33
    .line 34
    const-string v2, "firebase_"

    .line 35
    .line 36
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    sput-object v0, Lkj0/l;->c:Ljava/util/List;

    .line 45
    .line 46
    return-void
.end method

.method public static a(Lkj0/j;)V
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lkj0/j;->getName()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sget-object v1, Lkj0/l;->a:Lly0/n;

    .line 11
    .line 12
    invoke-virtual {v1, v0}, Lly0/n;->d(Ljava/lang/CharSequence;)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const-string v2, "User property name \'"

    .line 17
    .line 18
    if-eqz v1, :cond_6

    .line 19
    .line 20
    sget-object v1, Lkj0/l;->b:Ljava/util/List;

    .line 21
    .line 22
    invoke-interface {v1, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-nez v1, :cond_5

    .line 27
    .line 28
    sget-object v1, Lkj0/l;->c:Ljava/util/List;

    .line 29
    .line 30
    check-cast v1, Ljava/lang/Iterable;

    .line 31
    .line 32
    instance-of v3, v1, Ljava/util/Collection;

    .line 33
    .line 34
    if-eqz v3, :cond_0

    .line 35
    .line 36
    move-object v3, v1

    .line 37
    check-cast v3, Ljava/util/Collection;

    .line 38
    .line 39
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    if-eqz v3, :cond_0

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_0
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    if-eqz v3, :cond_2

    .line 55
    .line 56
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    check-cast v3, Ljava/lang/String;

    .line 61
    .line 62
    const/4 v4, 0x0

    .line 63
    invoke-static {v0, v3, v4}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    if-nez v3, :cond_1

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_1
    new-instance p0, Lkj0/k;

    .line 71
    .line 72
    const-string v1, "\' starts with reserved Firebase prefix!"

    .line 73
    .line 74
    invoke-static {v2, v0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    invoke-direct {p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    :cond_2
    :goto_1
    invoke-interface {p0}, Lkj0/j;->getValue()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    if-nez p0, :cond_3

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    const/16 v1, 0x24

    .line 94
    .line 95
    if-gt v0, v1, :cond_4

    .line 96
    .line 97
    :goto_2
    return-void

    .line 98
    :cond_4
    new-instance v0, Lkj0/k;

    .line 99
    .line 100
    const-string v1, "User property value \'"

    .line 101
    .line 102
    const-string v2, "\' is too long (max length is 36 chars)!"

    .line 103
    .line 104
    invoke-static {v1, p0, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    invoke-direct {v0, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    throw v0

    .line 112
    :cond_5
    new-instance p0, Lkj0/k;

    .line 113
    .line 114
    const-string v1, "\' is reserved by Firebase!"

    .line 115
    .line 116
    invoke-static {v2, v0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    invoke-direct {p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw p0

    .line 124
    :cond_6
    new-instance p0, Lkj0/k;

    .line 125
    .line 126
    const-string v1, "\' does not match valid format!"

    .line 127
    .line 128
    invoke-static {v2, v0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    invoke-direct {p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    throw p0
.end method
