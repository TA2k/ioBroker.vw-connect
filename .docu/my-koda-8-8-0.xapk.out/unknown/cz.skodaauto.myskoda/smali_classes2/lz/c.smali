.class public final Llz/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z


# direct methods
.method public constructor <init>(Z)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llz/c;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llz/c;->e:Z

    return-void
.end method

.method public constructor <init>(ZLlz/e;)V
    .locals 0

    const/4 p2, 0x0

    iput p2, p0, Llz/c;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llz/c;->e:Z

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Llz/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Llx0/b0;

    .line 7
    .line 8
    const-string v0, "$this$mapData"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-boolean p0, p0, Llz/c;->e:Z

    .line 14
    .line 15
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :pswitch_0
    check-cast p1, Lmz/f;

    .line 21
    .line 22
    const-string v0, "$this$mapData"

    .line 23
    .line 24
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    iget-boolean p0, p0, Llz/c;->e:Z

    .line 28
    .line 29
    if-eqz p0, :cond_0

    .line 30
    .line 31
    new-instance p0, Llz/m;

    .line 32
    .line 33
    sget-object v0, Ljava/time/ZoneOffset;->UTC:Ljava/time/ZoneOffset;

    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/time/ZoneId;->normalized()Ljava/time/ZoneId;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    const-string v1, "normalized(...)"

    .line 40
    .line 41
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    const-string v2, "systemDefault(...)"

    .line 49
    .line 50
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    iget-object v2, p1, Lmz/f;->g:Ljava/util/List;

    .line 54
    .line 55
    invoke-direct {p0, v0, v1, v2}, Llz/m;-><init>(Ljava/time/ZoneId;Ljava/time/ZoneId;Ljava/util/List;)V

    .line 56
    .line 57
    .line 58
    invoke-static {p0}, Llz/n;->a(Llz/m;)Ljava/util/ArrayList;

    .line 59
    .line 60
    .line 61
    move-result-object v11

    .line 62
    iget-object v4, p1, Lmz/f;->a:Ljava/time/OffsetDateTime;

    .line 63
    .line 64
    iget-object v5, p1, Lmz/f;->b:Lmz/e;

    .line 65
    .line 66
    iget-wide v6, p1, Lmz/f;->c:J

    .line 67
    .line 68
    iget-object v8, p1, Lmz/f;->d:Lmz/d;

    .line 69
    .line 70
    iget-object v9, p1, Lmz/f;->e:Lqr0/q;

    .line 71
    .line 72
    iget-object v10, p1, Lmz/f;->f:Ljava/util/List;

    .line 73
    .line 74
    iget-object v12, p1, Lmz/f;->h:Ljava/time/OffsetDateTime;

    .line 75
    .line 76
    iget-object v13, p1, Lmz/f;->i:Lmb0/c;

    .line 77
    .line 78
    new-instance v3, Lmz/f;

    .line 79
    .line 80
    invoke-direct/range {v3 .. v13}, Lmz/f;-><init>(Ljava/time/OffsetDateTime;Lmz/e;JLmz/d;Lqr0/q;Ljava/util/List;Ljava/util/List;Ljava/time/OffsetDateTime;Lmb0/c;)V

    .line 81
    .line 82
    .line 83
    move-object p1, v3

    .line 84
    :cond_0
    return-object p1

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
