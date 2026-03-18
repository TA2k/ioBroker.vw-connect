.class public final Luf/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Luf/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Luf/c;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Luf/c;->a:Luf/c;

    .line 7
    .line 8
    return-void
.end method

.method public static a(Lof/d;)Luf/q;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_3

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p0, v0, :cond_2

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    if-eq p0, v0, :cond_1

    .line 12
    .line 13
    const/4 v0, 0x3

    .line 14
    if-ne p0, v0, :cond_0

    .line 15
    .line 16
    sget-object p0, Luf/q;->g:Luf/q;

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    new-instance p0, La8/r0;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    sget-object p0, Luf/q;->f:Luf/q;

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_2
    sget-object p0, Luf/q;->e:Luf/q;

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_3
    sget-object p0, Luf/q;->d:Luf/q;

    .line 32
    .line 33
    return-object p0
.end method
