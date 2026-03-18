.class public final synthetic Le30/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Le30/q;


# direct methods
.method public synthetic constructor <init>(Le30/q;I)V
    .locals 0

    .line 1
    iput p2, p0, Le30/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le30/k;->e:Le30/q;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Le30/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Le30/n;

    .line 7
    .line 8
    iget-object p0, p0, Le30/k;->e:Le30/q;

    .line 9
    .line 10
    iget-object v1, p0, Le30/q;->h:Lij0/a;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    new-array v3, v2, [Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v1, Ljj0/f;

    .line 16
    .line 17
    const v4, 0x7f1203d2

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, v4, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    iget-object p0, p0, Le30/q;->h:Lij0/a;

    .line 25
    .line 26
    new-array v2, v2, [Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Ljj0/f;

    .line 29
    .line 30
    const v3, 0x7f1203d1

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-direct {v0, v1, p0}, Le30/n;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    return-object v0

    .line 41
    :pswitch_0
    new-instance v0, Le30/n;

    .line 42
    .line 43
    iget-object p0, p0, Le30/k;->e:Le30/q;

    .line 44
    .line 45
    iget-object v1, p0, Le30/q;->h:Lij0/a;

    .line 46
    .line 47
    const/4 v2, 0x0

    .line 48
    new-array v3, v2, [Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v1, Ljj0/f;

    .line 51
    .line 52
    const v4, 0x7f1203df

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1, v4, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    iget-object p0, p0, Le30/q;->h:Lij0/a;

    .line 60
    .line 61
    new-array v2, v2, [Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p0, Ljj0/f;

    .line 64
    .line 65
    const v3, 0x7f1203de

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-direct {v0, v1, p0}, Le30/n;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    return-object v0

    .line 76
    nop

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
