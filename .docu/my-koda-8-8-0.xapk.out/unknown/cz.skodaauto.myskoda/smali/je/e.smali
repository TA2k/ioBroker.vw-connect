.class public final synthetic Lje/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvz0/j;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lje/e;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final synthetic annotationType()Ljava/lang/Class;
    .locals 0

    .line 1
    iget p0, p0, Lje/e;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-class p0, Lvz0/j;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-class p0, Lvz0/j;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    const-class p0, Lvz0/j;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final synthetic discriminator()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lje/e;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "infrastructureType"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-string p0, "responseType"

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    const-string p0, "tariffType"

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget p0, p0, Lje/e;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of p0, p1, Lvz0/j;

    .line 7
    .line 8
    if-nez p0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    check-cast p1, Lvz0/j;

    .line 12
    .line 13
    const-string p0, "infrastructureType"

    .line 14
    .line 15
    invoke-interface {p1}, Lvz0/j;->discriminator()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-nez p0, :cond_1

    .line 24
    .line 25
    :goto_0
    const/4 p0, 0x0

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const/4 p0, 0x1

    .line 28
    :goto_1
    return p0

    .line 29
    :pswitch_0
    instance-of p0, p1, Lvz0/j;

    .line 30
    .line 31
    if-nez p0, :cond_2

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_2
    check-cast p1, Lvz0/j;

    .line 35
    .line 36
    const-string p0, "responseType"

    .line 37
    .line 38
    invoke-interface {p1}, Lvz0/j;->discriminator()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-nez p0, :cond_3

    .line 47
    .line 48
    :goto_2
    const/4 p0, 0x0

    .line 49
    goto :goto_3

    .line 50
    :cond_3
    const/4 p0, 0x1

    .line 51
    :goto_3
    return p0

    .line 52
    :pswitch_1
    instance-of p0, p1, Lvz0/j;

    .line 53
    .line 54
    if-nez p0, :cond_4

    .line 55
    .line 56
    goto :goto_4

    .line 57
    :cond_4
    check-cast p1, Lvz0/j;

    .line 58
    .line 59
    const-string p0, "tariffType"

    .line 60
    .line 61
    invoke-interface {p1}, Lvz0/j;->discriminator()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    if-nez p0, :cond_5

    .line 70
    .line 71
    :goto_4
    const/4 p0, 0x0

    .line 72
    goto :goto_5

    .line 73
    :cond_5
    const/4 p0, 0x1

    .line 74
    :goto_5
    return p0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Lje/e;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const p0, -0x61a487e7

    .line 7
    .line 8
    .line 9
    return p0

    .line 10
    :pswitch_0
    const p0, 0x7ff9087f

    .line 11
    .line 12
    .line 13
    return p0

    .line 14
    :pswitch_1
    const p0, -0x5272b2e6

    .line 15
    .line 16
    .line 17
    return p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lje/e;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "@kotlinx.serialization.json.JsonClassDiscriminator(discriminator=infrastructureType)"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-string p0, "@kotlinx.serialization.json.JsonClassDiscriminator(discriminator=responseType)"

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    const-string p0, "@kotlinx.serialization.json.JsonClassDiscriminator(discriminator=tariffType)"

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
