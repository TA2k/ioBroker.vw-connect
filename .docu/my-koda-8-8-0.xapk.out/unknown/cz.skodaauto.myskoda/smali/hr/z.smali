.class public abstract Lhr/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lhr/x;

.field public static final b:Lhr/y;

.field public static final c:Lhr/y;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lhr/x;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lhr/z;->a:Lhr/x;

    .line 7
    .line 8
    new-instance v0, Lhr/y;

    .line 9
    .line 10
    const/4 v1, -0x1

    .line 11
    invoke-direct {v0, v1}, Lhr/y;-><init>(I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lhr/z;->b:Lhr/y;

    .line 15
    .line 16
    new-instance v0, Lhr/y;

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    invoke-direct {v0, v1}, Lhr/y;-><init>(I)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lhr/z;->c:Lhr/y;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public abstract a(II)Lhr/z;
.end method

.method public abstract b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;
.end method

.method public abstract c(ZZ)Lhr/z;
.end method

.method public abstract d(ZZ)Lhr/z;
.end method

.method public abstract e()I
.end method
