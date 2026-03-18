.class public final Lic/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lic/s;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lic/s;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lic/s;->a:Lic/s;

    .line 7
    .line 8
    return-void
.end method

.method public static a(Ljava/util/List;)Lhc/a;
    .locals 7

    .line 1
    const-string v0, "content"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p0, Ljava/lang/Iterable;

    .line 7
    .line 8
    new-instance v0, Ljava/util/ArrayList;

    .line 9
    .line 10
    const/16 v1, 0xa

    .line 11
    .line 12
    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 17
    .line 18
    .line 19
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_3

    .line 28
    .line 29
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    check-cast v1, Ldc/q;

    .line 34
    .line 35
    new-instance v2, Lgl/f;

    .line 36
    .line 37
    iget-object v3, v1, Ldc/q;->e:Ljava/lang/String;

    .line 38
    .line 39
    const/4 v4, 0x1

    .line 40
    invoke-direct {v2, v3, v4}, Lgl/f;-><init>(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    sget-object v3, Lhc/b;->g:Lsx0/b;

    .line 44
    .line 45
    invoke-virtual {v3}, Lmx0/e;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    :cond_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    if-eqz v4, :cond_1

    .line 54
    .line 55
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    move-object v5, v4

    .line 60
    check-cast v5, Lhc/b;

    .line 61
    .line 62
    iget-object v5, v5, Lhc/b;->d:Ljava/lang/String;

    .line 63
    .line 64
    iget-object v6, v1, Ldc/q;->d:Ljava/lang/String;

    .line 65
    .line 66
    invoke-virtual {v5, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v5

    .line 70
    if-eqz v5, :cond_0

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_1
    const/4 v4, 0x0

    .line 74
    :goto_1
    check-cast v4, Lhc/b;

    .line 75
    .line 76
    if-nez v4, :cond_2

    .line 77
    .line 78
    sget-object v4, Lhc/b;->e:Lhc/b;

    .line 79
    .line 80
    :cond_2
    new-instance v1, Lhc/c;

    .line 81
    .line 82
    invoke-direct {v1, v2, v4}, Lhc/c;-><init>(Lgl/h;Lhc/b;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_3
    new-instance p0, Lhc/a;

    .line 90
    .line 91
    invoke-direct {p0, v0}, Lhc/a;-><init>(Ljava/util/ArrayList;)V

    .line 92
    .line 93
    .line 94
    return-object p0
.end method
