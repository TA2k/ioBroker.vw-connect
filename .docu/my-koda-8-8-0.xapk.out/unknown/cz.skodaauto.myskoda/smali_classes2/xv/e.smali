.class public final Lxv/e;
.super Lxv/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lxv/e;

.field public static final e:Lg4/g0;


# direct methods
.method static constructor <clinit>()V
    .locals 22

    .line 1
    new-instance v0, Lxv/e;

    .line 2
    .line 3
    const-string v1, "foo"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lxv/n;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lxv/e;->d:Lxv/e;

    .line 9
    .line 10
    new-instance v2, Lg4/g0;

    .line 11
    .line 12
    sget-object v7, Lk4/x;->n:Lk4/x;

    .line 13
    .line 14
    const/16 v20, 0x0

    .line 15
    .line 16
    const v21, 0xfffb

    .line 17
    .line 18
    .line 19
    const-wide/16 v3, 0x0

    .line 20
    .line 21
    const-wide/16 v5, 0x0

    .line 22
    .line 23
    const/4 v8, 0x0

    .line 24
    const/4 v9, 0x0

    .line 25
    const/4 v10, 0x0

    .line 26
    const/4 v11, 0x0

    .line 27
    const-wide/16 v12, 0x0

    .line 28
    .line 29
    const/4 v14, 0x0

    .line 30
    const/4 v15, 0x0

    .line 31
    const/16 v16, 0x0

    .line 32
    .line 33
    const-wide/16 v17, 0x0

    .line 34
    .line 35
    const/16 v19, 0x0

    .line 36
    .line 37
    invoke-direct/range {v2 .. v21}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 38
    .line 39
    .line 40
    sput-object v2, Lxv/e;->e:Lg4/g0;

    .line 41
    .line 42
    return-void
.end method


# virtual methods
.method public final a(Lxv/p;)Lg4/g0;
    .locals 0

    .line 1
    iget-object p0, p1, Lxv/p;->a:Lg4/g0;

    .line 2
    .line 3
    return-object p0
.end method
