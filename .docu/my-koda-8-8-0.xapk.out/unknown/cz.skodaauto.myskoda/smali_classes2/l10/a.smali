.class public abstract Ll10/a;
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
    new-instance v5, Lkz/a;

    .line 7
    .line 8
    const/4 v1, 0x2

    .line 9
    invoke-direct {v5, v1}, Lkz/a;-><init>(I)V

    .line 10
    .line 11
    .line 12
    sget-object v2, Li21/b;->e:Lh21/b;

    .line 13
    .line 14
    sget-object v6, La21/c;->e:La21/c;

    .line 15
    .line 16
    new-instance v1, La21/a;

    .line 17
    .line 18
    const-class v3, Lm10/d;

    .line 19
    .line 20
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 21
    .line 22
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    const/4 v4, 0x0

    .line 27
    invoke-direct/range {v1 .. v6}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 28
    .line 29
    .line 30
    invoke-static {v1, v0}, Lvj/b;->v(La21/a;Le21/a;)V

    .line 31
    .line 32
    .line 33
    sput-object v0, Ll10/a;->a:Le21/a;

    .line 34
    .line 35
    return-void
.end method
