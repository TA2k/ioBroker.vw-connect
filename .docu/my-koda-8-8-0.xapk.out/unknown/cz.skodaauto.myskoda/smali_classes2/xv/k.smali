.class public final Lxv/k;
.super Lxv/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lxv/k;

.field public static final e:Lg4/g0;


# direct methods
.method static constructor <clinit>()V
    .locals 21

    .line 1
    new-instance v0, Lxv/k;

    .line 2
    .line 3
    const-string v1, "subscript"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lxv/n;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lxv/k;->d:Lxv/k;

    .line 9
    .line 10
    const/16 v0, 0xa

    .line 11
    .line 12
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 13
    .line 14
    .line 15
    move-result-wide v4

    .line 16
    new-instance v1, Lg4/g0;

    .line 17
    .line 18
    new-instance v13, Lr4/a;

    .line 19
    .line 20
    const v0, -0x41b33333    # -0.2f

    .line 21
    .line 22
    .line 23
    invoke-direct {v13, v0}, Lr4/a;-><init>(F)V

    .line 24
    .line 25
    .line 26
    const/16 v19, 0x0

    .line 27
    .line 28
    const v20, 0xfefd

    .line 29
    .line 30
    .line 31
    const-wide/16 v2, 0x0

    .line 32
    .line 33
    const/4 v6, 0x0

    .line 34
    const/4 v7, 0x0

    .line 35
    const/4 v8, 0x0

    .line 36
    const/4 v9, 0x0

    .line 37
    const/4 v10, 0x0

    .line 38
    const-wide/16 v11, 0x0

    .line 39
    .line 40
    const/4 v14, 0x0

    .line 41
    const/4 v15, 0x0

    .line 42
    const-wide/16 v16, 0x0

    .line 43
    .line 44
    const/16 v18, 0x0

    .line 45
    .line 46
    invoke-direct/range {v1 .. v20}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 47
    .line 48
    .line 49
    sput-object v1, Lxv/k;->e:Lg4/g0;

    .line 50
    .line 51
    return-void
.end method


# virtual methods
.method public final a(Lxv/p;)Lg4/g0;
    .locals 0

    .line 1
    iget-object p0, p1, Lxv/p;->e:Lg4/g0;

    .line 2
    .line 3
    return-object p0
.end method
