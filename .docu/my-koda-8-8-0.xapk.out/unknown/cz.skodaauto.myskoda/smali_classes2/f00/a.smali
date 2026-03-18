.class public abstract Lf00/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Le21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Le21/a;

    .line 2
    .line 3
    invoke-direct {v0}, Le21/a;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v5, Lej0/a;

    .line 7
    .line 8
    const/16 v1, 0x1a

    .line 9
    .line 10
    invoke-direct {v5, v1}, Lej0/a;-><init>(I)V

    .line 11
    .line 12
    .line 13
    sget-object v2, Li21/b;->e:Lh21/b;

    .line 14
    .line 15
    sget-object v6, La21/c;->e:La21/c;

    .line 16
    .line 17
    new-instance v1, La21/a;

    .line 18
    .line 19
    const-class v3, Lh00/c;

    .line 20
    .line 21
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 22
    .line 23
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    const/4 v4, 0x0

    .line 28
    invoke-direct/range {v1 .. v6}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 29
    .line 30
    .line 31
    invoke-static {v1, v0}, Lvj/b;->v(La21/a;Le21/a;)V

    .line 32
    .line 33
    .line 34
    sput-object v0, Lf00/a;->a:Le21/a;

    .line 35
    .line 36
    return-void
.end method
