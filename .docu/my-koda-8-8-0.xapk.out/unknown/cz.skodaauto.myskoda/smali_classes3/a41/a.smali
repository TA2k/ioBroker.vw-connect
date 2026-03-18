.class public final La41/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh2/e8;


# instance fields
.field public final a:Ljava/util/List;

.field public final b:Ljava/util/Calendar;

.field public final c:Ljava/util/Calendar;


# direct methods
.method public constructor <init>(JLjava/lang/Integer;Ljava/util/List;)V
    .locals 1

    .line 1
    const-string v0, "disabledDays"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p4, p0, La41/a;->a:Ljava/util/List;

    .line 10
    .line 11
    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    .line 12
    .line 13
    .line 14
    move-result-object p4

    .line 15
    new-instance v0, Ljava/util/Date;

    .line 16
    .line 17
    invoke-direct {v0, p1, p2}, Ljava/util/Date;-><init>(J)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p4, v0}, Ljava/util/Calendar;->setTime(Ljava/util/Date;)V

    .line 21
    .line 22
    .line 23
    iput-object p4, p0, La41/a;->b:Ljava/util/Calendar;

    .line 24
    .line 25
    if-eqz p3, :cond_0

    .line 26
    .line 27
    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    .line 28
    .line 29
    .line 30
    move-result-object p4

    .line 31
    new-instance v0, Ljava/util/Date;

    .line 32
    .line 33
    invoke-direct {v0, p1, p2}, Ljava/util/Date;-><init>(J)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p4, v0}, Ljava/util/Calendar;->setTime(Ljava/util/Date;)V

    .line 37
    .line 38
    .line 39
    const/4 p1, 0x5

    .line 40
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    invoke-virtual {p4, p1, p2}, Ljava/util/Calendar;->add(II)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    const/4 p4, 0x0

    .line 49
    :goto_0
    iput-object p4, p0, La41/a;->c:Ljava/util/Calendar;

    .line 50
    .line 51
    return-void
.end method


# virtual methods
.method public final a(I)Z
    .locals 3

    .line 1
    const-string v0, "initialDay"

    .line 2
    .line 3
    iget-object v1, p0, La41/a;->b:Ljava/util/Calendar;

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    invoke-virtual {v1, v0}, Ljava/util/Calendar;->get(I)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    const/4 v2, 0x0

    .line 14
    if-lt p1, v1, :cond_0

    .line 15
    .line 16
    move v1, v0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v1, v2

    .line 19
    :goto_0
    iget-object p0, p0, La41/a;->c:Ljava/util/Calendar;

    .line 20
    .line 21
    if-eqz p0, :cond_2

    .line 22
    .line 23
    invoke-virtual {p0, v0}, Ljava/util/Calendar;->get(I)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-gt p1, p0, :cond_1

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move p0, v2

    .line 31
    goto :goto_2

    .line 32
    :cond_2
    :goto_1
    move p0, v0

    .line 33
    :goto_2
    if-eqz v1, :cond_3

    .line 34
    .line 35
    if-eqz p0, :cond_3

    .line 36
    .line 37
    return v0

    .line 38
    :cond_3
    return v2
.end method

.method public final b(J)Z
    .locals 3

    .line 1
    const-string v0, "initialDay"

    .line 2
    .line 3
    iget-object v1, p0, La41/a;->b:Ljava/util/Calendar;

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    new-instance v2, Ljava/util/Date;

    .line 13
    .line 14
    invoke-direct {v2, p1, p2}, Ljava/util/Date;-><init>(J)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v2}, Ljava/util/Calendar;->setTime(Ljava/util/Date;)V

    .line 18
    .line 19
    .line 20
    const/16 p1, 0xb

    .line 21
    .line 22
    const/16 p2, 0x17

    .line 23
    .line 24
    invoke-virtual {v0, p1, p2}, Ljava/util/Calendar;->set(II)V

    .line 25
    .line 26
    .line 27
    const/16 p1, 0xc

    .line 28
    .line 29
    const/16 p2, 0x3b

    .line 30
    .line 31
    invoke-virtual {v0, p1, p2}, Ljava/util/Calendar;->set(II)V

    .line 32
    .line 33
    .line 34
    const/16 p1, 0xd

    .line 35
    .line 36
    invoke-virtual {v0, p1, p2}, Ljava/util/Calendar;->set(II)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, v1}, Ljava/util/Calendar;->after(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    iget-object p2, p0, La41/a;->c:Ljava/util/Calendar;

    .line 44
    .line 45
    const/4 v1, 0x1

    .line 46
    if-eqz p2, :cond_0

    .line 47
    .line 48
    invoke-virtual {v0, p2}, Ljava/util/Calendar;->before(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result p2

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    move p2, v1

    .line 54
    :goto_0
    const/4 v2, 0x7

    .line 55
    invoke-virtual {v0, v2}, Ljava/util/Calendar;->get(I)I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    iget-object p0, p0, La41/a;->a:Ljava/util/List;

    .line 64
    .line 65
    invoke-interface {p0, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    if-eqz p1, :cond_1

    .line 70
    .line 71
    if-eqz p2, :cond_1

    .line 72
    .line 73
    if-nez p0, :cond_1

    .line 74
    .line 75
    return v1

    .line 76
    :cond_1
    const/4 p0, 0x0

    .line 77
    return p0
.end method
