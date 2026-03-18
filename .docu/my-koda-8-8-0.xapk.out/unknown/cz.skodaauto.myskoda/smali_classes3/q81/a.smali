.class public final Lq81/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Lv71/b;


# instance fields
.field public final a:Ll71/z;

.field public final b:Leb/j0;

.field public c:Lv71/b;

.field public final d:Lb6/f;

.field public e:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lv71/b;->i:Lv71/b;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-static {v0, v1}, Lv71/b;->a(Lv71/b;Z)Lv71/b;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    sput-object v0, Lq81/a;->f:Lv71/b;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Ll71/z;)V
    .locals 2

    .line 1
    new-instance v0, Lq81/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p1, v1}, Lq81/c;-><init>(Ll71/z;I)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lq81/a;->a:Ll71/z;

    .line 11
    .line 12
    iput-object v0, p0, Lq81/a;->b:Leb/j0;

    .line 13
    .line 14
    new-instance p1, Lb6/f;

    .line 15
    .line 16
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    iput-boolean v0, p1, Lb6/f;->d:Z

    .line 21
    .line 22
    iput-object p1, p0, Lq81/a;->d:Lb6/f;

    .line 23
    .line 24
    return-void
.end method
