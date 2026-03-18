.class public final Lh11/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh11/g;


# static fields
.field public static final a:Ljava/util/regex/Pattern;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "^[!\"#$%&\'()*+,./:;<=>?@\\[\\\\\\]^_`{|}~-]"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lh11/c;->a:Ljava/util/regex/Pattern;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final a(Lg11/l;)Lvp/y1;
    .locals 3

    .line 1
    iget-object p0, p1, Lg11/l;->e:Lh11/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lh11/h;->j()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lh11/h;->m()C

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    const/16 v0, 0xa

    .line 11
    .line 12
    if-ne p1, v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Lh11/h;->j()V

    .line 15
    .line 16
    .line 17
    new-instance p1, Lj11/i;

    .line 18
    .line 19
    invoke-direct {p1}, Lj11/s;-><init>()V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lh11/h;->n()Lb8/i;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    new-instance v0, Lvp/y1;

    .line 27
    .line 28
    const/16 v1, 0x8

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    invoke-direct {v0, p1, p0, v2, v1}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 32
    .line 33
    .line 34
    return-object v0

    .line 35
    :cond_0
    sget-object v0, Lh11/c;->a:Ljava/util/regex/Pattern;

    .line 36
    .line 37
    invoke-static {p1}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-virtual {v0, v1}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->matches()Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-eqz v0, :cond_1

    .line 50
    .line 51
    invoke-virtual {p0}, Lh11/h;->j()V

    .line 52
    .line 53
    .line 54
    new-instance v0, Lj11/y;

    .line 55
    .line 56
    invoke-static {p1}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    invoke-direct {v0, p1}, Lj11/y;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {p0}, Lh11/h;->n()Lb8/i;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    new-instance p1, Lvp/y1;

    .line 68
    .line 69
    const/16 v1, 0x8

    .line 70
    .line 71
    const/4 v2, 0x0

    .line 72
    invoke-direct {p1, v0, p0, v2, v1}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 73
    .line 74
    .line 75
    return-object p1

    .line 76
    :cond_1
    new-instance p1, Lj11/y;

    .line 77
    .line 78
    const-string v0, "\\"

    .line 79
    .line 80
    invoke-direct {p1, v0}, Lj11/y;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p0}, Lh11/h;->n()Lb8/i;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    new-instance v0, Lvp/y1;

    .line 88
    .line 89
    const/16 v1, 0x8

    .line 90
    .line 91
    const/4 v2, 0x0

    .line 92
    invoke-direct {v0, p1, p0, v2, v1}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 93
    .line 94
    .line 95
    return-object v0
.end method
