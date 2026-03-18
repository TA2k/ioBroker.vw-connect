.class public abstract Lh2/g8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ls1/e;

.field public static final b:Ls1/e;

.field public static final c:Ls1/e;

.field public static final d:Ls1/e;

.field public static final e:Ls1/e;

.field public static final f:Ls1/e;

.field public static final g:Ls1/e;

.field public static final h:Ls1/e;

.field public static final i:Ls1/b;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lk2/g0;->d:Ls1/e;

    .line 2
    .line 3
    sput-object v0, Lh2/g8;->a:Ls1/e;

    .line 4
    .line 5
    sget-object v0, Lk2/g0;->h:Ls1/e;

    .line 6
    .line 7
    sput-object v0, Lh2/g8;->b:Ls1/e;

    .line 8
    .line 9
    sget-object v0, Lk2/g0;->g:Ls1/e;

    .line 10
    .line 11
    sput-object v0, Lh2/g8;->c:Ls1/e;

    .line 12
    .line 13
    sget-object v0, Lk2/g0;->e:Ls1/e;

    .line 14
    .line 15
    sput-object v0, Lh2/g8;->d:Ls1/e;

    .line 16
    .line 17
    sget-object v0, Lk2/g0;->f:Ls1/e;

    .line 18
    .line 19
    sput-object v0, Lh2/g8;->e:Ls1/e;

    .line 20
    .line 21
    sget-object v0, Lk2/g0;->b:Ls1/e;

    .line 22
    .line 23
    sput-object v0, Lh2/g8;->f:Ls1/e;

    .line 24
    .line 25
    sget-object v0, Lk2/g0;->c:Ls1/e;

    .line 26
    .line 27
    sput-object v0, Lh2/g8;->g:Ls1/e;

    .line 28
    .line 29
    sget-object v0, Lk2/g0;->a:Ls1/e;

    .line 30
    .line 31
    sput-object v0, Lh2/g8;->h:Ls1/e;

    .line 32
    .line 33
    sget-object v0, Lk2/g0;->i:Ls1/b;

    .line 34
    .line 35
    sput-object v0, Lh2/g8;->i:Ls1/b;

    .line 36
    .line 37
    const/16 v0, 0x64

    .line 38
    .line 39
    int-to-float v0, v0

    .line 40
    const/4 v1, 0x0

    .line 41
    cmpg-float v1, v0, v1

    .line 42
    .line 43
    if-ltz v1, :cond_0

    .line 44
    .line 45
    const/high16 v1, 0x42c80000    # 100.0f

    .line 46
    .line 47
    cmpl-float v0, v0, v1

    .line 48
    .line 49
    if-lez v0, :cond_1

    .line 50
    .line 51
    :cond_0
    const-string v0, "The percent should be in the range of [0, 100]"

    .line 52
    .line 53
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    :cond_1
    return-void
.end method
