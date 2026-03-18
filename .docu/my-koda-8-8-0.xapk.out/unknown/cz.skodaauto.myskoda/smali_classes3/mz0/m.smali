.class public final Lmz0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Lmz0/m;

.field public static final b:Luz0/h1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lmz0/m;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lmz0/m;->a:Lmz0/m;

    .line 7
    .line 8
    const-string v0, "kotlinx.datetime.UtcOffset"

    .line 9
    .line 10
    invoke-static {v0}, Lkp/x8;->a(Ljava/lang/String;)Luz0/h1;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lmz0/m;->b:Luz0/h1;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object p0, Lgz0/d0;->Companion:Lgz0/c0;

    .line 2
    .line 3
    invoke-interface {p1}, Ltz0/c;->x()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lhz0/u1;->a:Llx0/q;

    .line 8
    .line 9
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Lhz0/s1;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    const-string p0, "input"

    .line 19
    .line 20
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string p0, "format"

    .line 24
    .line 25
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    check-cast p0, Lhz0/s1;

    .line 33
    .line 34
    if-ne v1, p0, :cond_0

    .line 35
    .line 36
    sget-object p0, Lgz0/g0;->a:Llx0/q;

    .line 37
    .line 38
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    check-cast p0, Ljava/time/format/DateTimeFormatter;

    .line 43
    .line 44
    const-string v0, "access$getIsoFormat(...)"

    .line 45
    .line 46
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-static {p1, p0}, Lgz0/g0;->a(Ljava/lang/String;Ljava/time/format/DateTimeFormatter;)Lgz0/d0;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :cond_0
    sget-object p0, Lhz0/u1;->b:Llx0/q;

    .line 55
    .line 56
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    check-cast p0, Lhz0/s1;

    .line 61
    .line 62
    if-ne v1, p0, :cond_1

    .line 63
    .line 64
    sget-object p0, Lgz0/g0;->b:Llx0/q;

    .line 65
    .line 66
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    check-cast p0, Ljava/time/format/DateTimeFormatter;

    .line 71
    .line 72
    const-string v0, "access$getIsoBasicFormat(...)"

    .line 73
    .line 74
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    invoke-static {p1, p0}, Lgz0/g0;->a(Ljava/lang/String;Ljava/time/format/DateTimeFormatter;)Lgz0/d0;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0

    .line 82
    :cond_1
    sget-object p0, Lhz0/u1;->c:Llx0/q;

    .line 83
    .line 84
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    check-cast p0, Lhz0/s1;

    .line 89
    .line 90
    if-ne v1, p0, :cond_2

    .line 91
    .line 92
    sget-object p0, Lgz0/g0;->c:Llx0/q;

    .line 93
    .line 94
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    check-cast p0, Ljava/time/format/DateTimeFormatter;

    .line 99
    .line 100
    const-string v0, "access$getFourDigitsFormat(...)"

    .line 101
    .line 102
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    invoke-static {p1, p0}, Lgz0/g0;->a(Ljava/lang/String;Ljava/time/format/DateTimeFormatter;)Lgz0/d0;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    return-object p0

    .line 110
    :cond_2
    invoke-virtual {v1, p1}, Lhz0/a;->c(Ljava/lang/CharSequence;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    check-cast p0, Lgz0/d0;

    .line 115
    .line 116
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lmz0/m;->b:Luz0/h1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Lgz0/d0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p2}, Lgz0/d0;->toString()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-interface {p1, p0}, Ltz0/d;->E(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
