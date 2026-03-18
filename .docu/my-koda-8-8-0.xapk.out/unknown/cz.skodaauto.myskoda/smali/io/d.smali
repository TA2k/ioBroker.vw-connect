.class public final synthetic Lio/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/b;
.implements Laq/i;


# static fields
.field public static final synthetic e:Lio/d;

.field public static final synthetic f:Lio/d;

.field public static final synthetic g:Lio/d;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/d;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lio/d;->e:Lio/d;

    .line 8
    .line 9
    new-instance v0, Lio/d;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lio/d;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lio/d;->f:Lio/d;

    .line 16
    .line 17
    new-instance v0, Lio/d;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lio/d;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lio/d;->g:Lio/d;

    .line 24
    .line 25
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lio/d;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public g(Ljava/lang/Object;)Laq/t;
    .locals 0

    .line 1
    check-cast p1, Landroid/os/Bundle;

    .line 2
    .line 3
    sget p0, Lio/b;->h:I

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    const-string p0, "google.messenger"

    .line 8
    .line 9
    invoke-virtual {p1, p0}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x0

    .line 16
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :cond_0
    invoke-static {p1}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method public w(Laq/j;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lio/d;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Laq/j;->g()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Landroid/os/Bundle;

    .line 11
    .line 12
    const-string p1, "notification_data"

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Landroid/content/Intent;

    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    new-instance p1, Lio/a;

    .line 23
    .line 24
    invoke-direct {p1, p0}, Lio/a;-><init>(Landroid/content/Intent;)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p1, 0x0

    .line 29
    :goto_0
    return-object p1

    .line 30
    :pswitch_0
    invoke-virtual {p1}, Laq/j;->i()Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_1

    .line 35
    .line 36
    invoke-virtual {p1}, Laq/j;->g()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Landroid/os/Bundle;

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_1
    const/4 p0, 0x3

    .line 44
    const-string v0, "Rpc"

    .line 45
    .line 46
    invoke-static {v0, p0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-nez p0, :cond_2

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    invoke-virtual {p1}, Laq/j;->f()Ljava/lang/Exception;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    const-string v1, "Error making request: "

    .line 62
    .line 63
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 68
    .line 69
    .line 70
    :goto_1
    new-instance p0, Ljava/io/IOException;

    .line 71
    .line 72
    invoke-virtual {p1}, Laq/j;->f()Ljava/lang/Exception;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    const-string v0, "SERVICE_NOT_AVAILABLE"

    .line 77
    .line 78
    invoke-direct {p0, v0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    nop

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
