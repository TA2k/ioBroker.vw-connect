.class public final Lxv/f;
.super Lxv/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lxv/f;

.field public static final e:Lg4/g0;


# direct methods
.method static constructor <clinit>()V
    .locals 22

    .line 1
    new-instance v0, Lxv/f;

    .line 2
    .line 3
    const-string v1, "code"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lxv/n;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lxv/f;->d:Lxv/f;

    .line 9
    .line 10
    sget-object v7, Lk4/x;->m:Lk4/x;

    .line 11
    .line 12
    sget-wide v17, Lvv/j;->b:J

    .line 13
    .line 14
    new-instance v2, Lg4/g0;

    .line 15
    .line 16
    const/16 v20, 0x0

    .line 17
    .line 18
    const v21, 0xf7db

    .line 19
    .line 20
    .line 21
    const-wide/16 v3, 0x0

    .line 22
    .line 23
    const-wide/16 v5, 0x0

    .line 24
    .line 25
    const/4 v8, 0x0

    .line 26
    const/4 v9, 0x0

    .line 27
    sget-object v10, Lk4/n;->g:Lk4/z;

    .line 28
    .line 29
    const/4 v11, 0x0

    .line 30
    const-wide/16 v12, 0x0

    .line 31
    .line 32
    const/4 v14, 0x0

    .line 33
    const/4 v15, 0x0

    .line 34
    const/16 v16, 0x0

    .line 35
    .line 36
    const/16 v19, 0x0

    .line 37
    .line 38
    invoke-direct/range {v2 .. v21}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 39
    .line 40
    .line 41
    sput-object v2, Lxv/f;->e:Lg4/g0;

    .line 42
    .line 43
    return-void
.end method


# virtual methods
.method public final a(Lxv/p;)Lg4/g0;
    .locals 0

    .line 1
    iget-object p0, p1, Lxv/p;->g:Lg4/g0;

    .line 2
    .line 3
    return-object p0
.end method
