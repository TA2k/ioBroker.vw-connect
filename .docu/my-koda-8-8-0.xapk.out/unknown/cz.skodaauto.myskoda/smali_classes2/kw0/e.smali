.class public final Lkw0/e;
.super Lyw0/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final g:Lj51/i;

.field public static final h:Lj51/i;

.field public static final i:Lj51/i;

.field public static final j:Lj51/i;

.field public static final k:Lj51/i;

.field public static final l:Lj51/i;

.field public static final m:Lj51/i;

.field public static final n:Lj51/i;

.field public static final o:Lj51/i;

.field public static final p:Lj51/i;


# instance fields
.field public final synthetic e:I

.field public final f:Z


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lj51/i;

    .line 2
    .line 3
    const-string v1, "Before"

    .line 4
    .line 5
    const/4 v2, 0x6

    .line 6
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lkw0/e;->g:Lj51/i;

    .line 10
    .line 11
    new-instance v0, Lj51/i;

    .line 12
    .line 13
    const-string v1, "State"

    .line 14
    .line 15
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 16
    .line 17
    .line 18
    sput-object v0, Lkw0/e;->h:Lj51/i;

    .line 19
    .line 20
    new-instance v0, Lj51/i;

    .line 21
    .line 22
    const-string v1, "Transform"

    .line 23
    .line 24
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    sput-object v0, Lkw0/e;->i:Lj51/i;

    .line 28
    .line 29
    new-instance v0, Lj51/i;

    .line 30
    .line 31
    const-string v1, "Render"

    .line 32
    .line 33
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 34
    .line 35
    .line 36
    sput-object v0, Lkw0/e;->j:Lj51/i;

    .line 37
    .line 38
    new-instance v0, Lj51/i;

    .line 39
    .line 40
    const-string v1, "Send"

    .line 41
    .line 42
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 43
    .line 44
    .line 45
    sput-object v0, Lkw0/e;->k:Lj51/i;

    .line 46
    .line 47
    new-instance v0, Lj51/i;

    .line 48
    .line 49
    const-string v1, "Before"

    .line 50
    .line 51
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 52
    .line 53
    .line 54
    sput-object v0, Lkw0/e;->l:Lj51/i;

    .line 55
    .line 56
    new-instance v0, Lj51/i;

    .line 57
    .line 58
    const-string v1, "State"

    .line 59
    .line 60
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 61
    .line 62
    .line 63
    sput-object v0, Lkw0/e;->m:Lj51/i;

    .line 64
    .line 65
    new-instance v0, Lj51/i;

    .line 66
    .line 67
    const-string v1, "Monitoring"

    .line 68
    .line 69
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 70
    .line 71
    .line 72
    sput-object v0, Lkw0/e;->n:Lj51/i;

    .line 73
    .line 74
    new-instance v0, Lj51/i;

    .line 75
    .line 76
    const-string v1, "Engine"

    .line 77
    .line 78
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 79
    .line 80
    .line 81
    sput-object v0, Lkw0/e;->o:Lj51/i;

    .line 82
    .line 83
    new-instance v0, Lj51/i;

    .line 84
    .line 85
    const-string v1, "Receive"

    .line 86
    .line 87
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    sput-object v0, Lkw0/e;->p:Lj51/i;

    .line 91
    .line 92
    return-void
.end method

.method public constructor <init>(I)V
    .locals 4

    .line 1
    iput p1, p0, Lkw0/e;->e:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p1, Lkw0/e;->j:Lj51/i;

    .line 7
    .line 8
    sget-object v0, Lkw0/e;->k:Lj51/i;

    .line 9
    .line 10
    sget-object v1, Lkw0/e;->g:Lj51/i;

    .line 11
    .line 12
    sget-object v2, Lkw0/e;->h:Lj51/i;

    .line 13
    .line 14
    sget-object v3, Lkw0/e;->i:Lj51/i;

    .line 15
    .line 16
    filled-new-array {v1, v2, v3, p1, v0}, [Lj51/i;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-direct {p0, p1}, Lyw0/d;-><init>([Lj51/i;)V

    .line 21
    .line 22
    .line 23
    const/4 p1, 0x1

    .line 24
    iput-boolean p1, p0, Lkw0/e;->f:Z

    .line 25
    .line 26
    return-void

    .line 27
    :pswitch_0
    sget-object p1, Lkw0/e;->o:Lj51/i;

    .line 28
    .line 29
    sget-object v0, Lkw0/e;->p:Lj51/i;

    .line 30
    .line 31
    sget-object v1, Lkw0/e;->l:Lj51/i;

    .line 32
    .line 33
    sget-object v2, Lkw0/e;->m:Lj51/i;

    .line 34
    .line 35
    sget-object v3, Lkw0/e;->n:Lj51/i;

    .line 36
    .line 37
    filled-new-array {v1, v2, v3, p1, v0}, [Lj51/i;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-direct {p0, p1}, Lyw0/d;-><init>([Lj51/i;)V

    .line 42
    .line 43
    .line 44
    const/4 p1, 0x1

    .line 45
    iput-boolean p1, p0, Lkw0/e;->f:Z

    .line 46
    .line 47
    return-void

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final d()Z
    .locals 1

    .line 1
    iget v0, p0, Lkw0/e;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-boolean p0, p0, Lkw0/e;->f:Z

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_0
    iget-boolean p0, p0, Lkw0/e;->f:Z

    .line 10
    .line 11
    return p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
