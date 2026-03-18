.class public final Ly6/h;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# static fields
.field public static final g:Ly6/h;

.field public static final h:Ly6/h;

.field public static final i:Ly6/h;

.field public static final j:Ly6/h;

.field public static final k:Ly6/h;

.field public static final l:Ly6/h;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ly6/h;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Ly6/h;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Ly6/h;->g:Ly6/h;

    .line 9
    .line 10
    new-instance v0, Ly6/h;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Ly6/h;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Ly6/h;->h:Ly6/h;

    .line 17
    .line 18
    new-instance v0, Ly6/h;

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-direct {v0, v1, v2}, Ly6/h;-><init>(II)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Ly6/h;->i:Ly6/h;

    .line 25
    .line 26
    new-instance v0, Ly6/h;

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    invoke-direct {v0, v1, v2}, Ly6/h;-><init>(II)V

    .line 30
    .line 31
    .line 32
    sput-object v0, Ly6/h;->j:Ly6/h;

    .line 33
    .line 34
    new-instance v0, Ly6/h;

    .line 35
    .line 36
    const/4 v2, 0x4

    .line 37
    invoke-direct {v0, v1, v2}, Ly6/h;-><init>(II)V

    .line 38
    .line 39
    .line 40
    sput-object v0, Ly6/h;->k:Ly6/h;

    .line 41
    .line 42
    new-instance v0, Ly6/h;

    .line 43
    .line 44
    const/4 v2, 0x5

    .line 45
    invoke-direct {v0, v1, v2}, Ly6/h;-><init>(II)V

    .line 46
    .line 47
    .line 48
    sput-object v0, Ly6/h;->l:Ly6/h;

    .line 49
    .line 50
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Ly6/h;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Ly6/h;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p2, Ly6/p;

    .line 7
    .line 8
    instance-of p0, p2, Lg7/a;

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    move-object p1, p2

    .line 13
    :cond_0
    return-object p1

    .line 14
    :pswitch_0
    check-cast p1, Ly6/m;

    .line 15
    .line 16
    check-cast p2, Ly6/g;

    .line 17
    .line 18
    if-eqz p2, :cond_1

    .line 19
    .line 20
    iget-object p0, p2, Ly6/g;->a:Ly6/t;

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    const/4 p0, 0x0

    .line 24
    :goto_0
    iput-object p0, p1, Ly6/m;->c:Ly6/t;

    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_1
    check-cast p1, Ly6/m;

    .line 30
    .line 31
    check-cast p2, Lf7/j;

    .line 32
    .line 33
    iget p0, p2, Lf7/j;->a:I

    .line 34
    .line 35
    iput p0, p1, Ly6/m;->d:I

    .line 36
    .line 37
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_2
    check-cast p1, Ly6/m;

    .line 41
    .line 42
    check-cast p2, Ly6/q;

    .line 43
    .line 44
    iput-object p2, p1, Ly6/m;->a:Ly6/q;

    .line 45
    .line 46
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object p0

    .line 49
    :pswitch_3
    check-cast p1, Ly6/m;

    .line 50
    .line 51
    check-cast p2, Ly6/s;

    .line 52
    .line 53
    iput-object p2, p1, Ly6/m;->b:Ly6/s;

    .line 54
    .line 55
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_4
    check-cast p1, Ljava/lang/String;

    .line 59
    .line 60
    check-cast p2, Ly6/p;

    .line 61
    .line 62
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    if-nez p0, :cond_2

    .line 67
    .line 68
    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    goto :goto_1

    .line 73
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 74
    .line 75
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string p1, ", "

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    :goto_1
    return-object p0

    .line 94
    nop

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
