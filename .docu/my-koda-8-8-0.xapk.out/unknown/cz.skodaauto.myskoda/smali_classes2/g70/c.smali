.class public final synthetic Lg70/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/io/IOException;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/io/IOException;I)V
    .locals 0

    .line 1
    iput p3, p0, Lg70/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg70/c;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lg70/c;->f:Ljava/io/IOException;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lg70/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lne0/c;

    .line 7
    .line 8
    new-instance v2, Ljava/lang/IllegalStateException;

    .line 9
    .line 10
    const-string v0, "Enrollment QR code help: cannot open link to the More information page. Url: "

    .line 11
    .line 12
    iget-object v3, p0, Lg70/c;->e:Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {v0, v3}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-object p0, p0, Lg70/c;->f:Ljava/io/IOException;

    .line 19
    .line 20
    invoke-direct {v2, v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 21
    .line 22
    .line 23
    const/4 v5, 0x0

    .line 24
    const/16 v6, 0x1e

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 29
    .line 30
    .line 31
    return-object v1

    .line 32
    :pswitch_0
    new-instance v2, Lne0/c;

    .line 33
    .line 34
    new-instance v3, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    const-string v0, "Enrollment QR code help: cannot open link to the More information page. Url: "

    .line 37
    .line 38
    iget-object v1, p0, Lg70/c;->e:Ljava/lang/String;

    .line 39
    .line 40
    invoke-static {v0, v1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    iget-object p0, p0, Lg70/c;->f:Ljava/io/IOException;

    .line 45
    .line 46
    invoke-direct {v3, v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 47
    .line 48
    .line 49
    const/4 v6, 0x0

    .line 50
    const/16 v7, 0x1e

    .line 51
    .line 52
    const/4 v4, 0x0

    .line 53
    const/4 v5, 0x0

    .line 54
    invoke-direct/range {v2 .. v7}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 55
    .line 56
    .line 57
    return-object v2

    .line 58
    :pswitch_1
    new-instance v3, Lne0/c;

    .line 59
    .line 60
    new-instance v4, Ljava/lang/IllegalStateException;

    .line 61
    .line 62
    const-string v0, "Remote Parking QR code help: cannot open link to the More information page. Url: "

    .line 63
    .line 64
    iget-object v1, p0, Lg70/c;->e:Ljava/lang/String;

    .line 65
    .line 66
    invoke-static {v0, v1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    iget-object p0, p0, Lg70/c;->f:Ljava/io/IOException;

    .line 71
    .line 72
    invoke-direct {v4, v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 73
    .line 74
    .line 75
    const/4 v7, 0x0

    .line 76
    const/16 v8, 0x1e

    .line 77
    .line 78
    const/4 v5, 0x0

    .line 79
    const/4 v6, 0x0

    .line 80
    invoke-direct/range {v3 .. v8}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 81
    .line 82
    .line 83
    return-object v3

    .line 84
    nop

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
