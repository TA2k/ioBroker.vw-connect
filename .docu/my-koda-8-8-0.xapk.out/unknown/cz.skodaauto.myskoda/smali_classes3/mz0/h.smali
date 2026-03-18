.class public final Lmz0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Lmz0/h;

.field public static final b:Luz0/h1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lmz0/h;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lmz0/h;->a:Lmz0/h;

    .line 7
    .line 8
    const-string v0, "kotlinx.datetime.LocalDateTime"

    .line 9
    .line 10
    invoke-static {v0}, Lkp/x8;->a(Ljava/lang/String;)Luz0/h1;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lmz0/h;->b:Luz0/h1;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object p0, Lgz0/w;->Companion:Lgz0/u;

    .line 2
    .line 3
    invoke-interface {p1}, Ltz0/c;->x()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lgz0/v;->a:Lhz0/q0;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    const-string p0, "input"

    .line 13
    .line 14
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v1, "format"

    .line 18
    .line 19
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    :try_start_0
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const/16 p1, 0xc

    .line 34
    .line 35
    invoke-static {p1, p0}, Liz0/b;->b(ILjava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-static {p0}, Ljava/time/LocalDateTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalDateTime;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    new-instance p1, Lgz0/w;

    .line 44
    .line 45
    invoke-direct {p1, p0}, Lgz0/w;-><init>(Ljava/time/LocalDateTime;)V
    :try_end_0
    .catch Ljava/time/format/DateTimeParseException; {:try_start_0 .. :try_end_0} :catch_0

    .line 46
    .line 47
    .line 48
    return-object p1

    .line 49
    :catch_0
    move-exception p0

    .line 50
    new-instance p1, Lgz0/a;

    .line 51
    .line 52
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    .line 53
    .line 54
    .line 55
    throw p1
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lmz0/h;->b:Luz0/h1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Lgz0/w;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p2}, Lgz0/w;->toString()Ljava/lang/String;

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
