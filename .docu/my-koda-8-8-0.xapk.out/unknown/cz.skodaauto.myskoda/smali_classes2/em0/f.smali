.class public final Lem0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lla/u;

.field public final b:Lem0/d;

.field public final c:Lem0/e;


# direct methods
.method public constructor <init>(Lla/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lem0/f;->a:Lla/u;

    .line 5
    .line 6
    new-instance p1, Lem0/d;

    .line 7
    .line 8
    invoke-direct {p1, p0}, Lem0/d;-><init>(Lem0/f;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lem0/f;->b:Lem0/d;

    .line 12
    .line 13
    new-instance p1, Lem0/e;

    .line 14
    .line 15
    invoke-direct {p1, p0}, Lem0/e;-><init>(Lem0/f;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lem0/f;->c:Lem0/e;

    .line 19
    .line 20
    return-void
.end method

.method public static a(Ljava/lang/String;)Lhm0/c;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :sswitch_0
    const-string v0, "OperationRequest"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    sget-object p0, Lhm0/c;->f:Lhm0/c;

    .line 18
    .line 19
    return-object p0

    .line 20
    :sswitch_1
    const-string v0, "ApiRequest"

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    sget-object p0, Lhm0/c;->d:Lhm0/c;

    .line 29
    .line 30
    return-object p0

    .line 31
    :sswitch_2
    const-string v0, "AsyncEvent"

    .line 32
    .line 33
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    sget-object p0, Lhm0/c;->g:Lhm0/c;

    .line 40
    .line 41
    return-object p0

    .line 42
    :sswitch_3
    const-string v0, "PushNotification"

    .line 43
    .line 44
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_0

    .line 49
    .line 50
    sget-object p0, Lhm0/c;->e:Lhm0/c;

    .line 51
    .line 52
    return-object p0

    .line 53
    :cond_0
    :goto_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 54
    .line 55
    const-string v1, "Can\'t convert value to enum, unknown value: "

    .line 56
    .line 57
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :sswitch_data_0
    .sparse-switch
        0x17fef945 -> :sswitch_3
        0x22b2899e -> :sswitch_2
        0x24793b35 -> :sswitch_1
        0x63e06748 -> :sswitch_0
    .end sparse-switch
.end method

.method public static final b(Lem0/f;Lhm0/c;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_3

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    if-eq p0, p1, :cond_2

    .line 9
    .line 10
    const/4 p1, 0x2

    .line 11
    if-eq p0, p1, :cond_1

    .line 12
    .line 13
    const/4 p1, 0x3

    .line 14
    if-ne p0, p1, :cond_0

    .line 15
    .line 16
    const-string p0, "AsyncEvent"

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
    const-string p0, "OperationRequest"

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_2
    const-string p0, "PushNotification"

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_3
    const-string p0, "ApiRequest"

    .line 32
    .line 33
    return-object p0
.end method
