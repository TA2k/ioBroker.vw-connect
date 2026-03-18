.class public final Lh11/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh11/g;


# static fields
.field public static final a:Ljava/util/regex/Pattern;

.field public static final b:Ljava/util/regex/Pattern;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "^[a-zA-Z][a-zA-Z0-9.+-]{1,31}:[^<>\u0000- ]*$"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lh11/b;->a:Ljava/util/regex/Pattern;

    .line 8
    .line 9
    const-string v0, "^([a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)$"

    .line 10
    .line 11
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lh11/b;->b:Ljava/util/regex/Pattern;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a(Lg11/l;)Lvp/y1;
    .locals 4

    .line 1
    iget-object p0, p1, Lg11/l;->e:Lh11/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lh11/h;->j()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lh11/h;->n()Lb8/i;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    const/16 v0, 0x3e

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lh11/h;->c(C)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v1, 0x0

    .line 17
    if-lez v0, :cond_2

    .line 18
    .line 19
    invoke-virtual {p0}, Lh11/h;->n()Lb8/i;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-virtual {p0, p1, v0}, Lh11/h;->e(Lb8/i;Lb8/i;)Lbn/c;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-virtual {p1}, Lbn/c;->i()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-virtual {p0}, Lh11/h;->j()V

    .line 32
    .line 33
    .line 34
    sget-object v2, Lh11/b;->a:Ljava/util/regex/Pattern;

    .line 35
    .line 36
    invoke-virtual {v2, v0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    invoke-virtual {v2}, Ljava/util/regex/Matcher;->matches()Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_0

    .line 45
    .line 46
    move-object v2, v0

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    sget-object v2, Lh11/b;->b:Ljava/util/regex/Pattern;

    .line 49
    .line 50
    invoke-virtual {v2, v0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    invoke-virtual {v2}, Ljava/util/regex/Matcher;->matches()Z

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    if-eqz v2, :cond_1

    .line 59
    .line 60
    const-string v2, "mailto:"

    .line 61
    .line 62
    invoke-static {v2, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    goto :goto_0

    .line 67
    :cond_1
    move-object v2, v1

    .line 68
    :goto_0
    if-eqz v2, :cond_2

    .line 69
    .line 70
    new-instance v3, Lj11/o;

    .line 71
    .line 72
    invoke-direct {v3, v2, v1}, Lj11/o;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    new-instance v1, Lj11/y;

    .line 76
    .line 77
    invoke-direct {v1, v0}, Lj11/y;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p1}, Lbn/c;->k()Ljava/util/ArrayList;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    invoke-virtual {v1, p1}, Lj11/s;->g(Ljava/util/List;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v3, v1}, Lj11/s;->c(Lj11/s;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0}, Lh11/h;->n()Lb8/i;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    new-instance p1, Lvp/y1;

    .line 95
    .line 96
    const/16 v0, 0x8

    .line 97
    .line 98
    const/4 v1, 0x0

    .line 99
    invoke-direct {p1, v3, p0, v1, v0}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 100
    .line 101
    .line 102
    return-object p1

    .line 103
    :cond_2
    return-object v1
.end method
