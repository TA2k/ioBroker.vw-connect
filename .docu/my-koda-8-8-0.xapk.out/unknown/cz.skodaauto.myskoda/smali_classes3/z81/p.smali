.class public abstract Lz81/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lyy0/c2;

.field public static final b:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lz81/q;

    .line 2
    .line 3
    sget-object v1, Lz81/f;->d:Lz81/f;

    .line 4
    .line 5
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sput-object v0, Lz81/p;->a:Lyy0/c2;

    .line 13
    .line 14
    const-string v0, "cat.tracing.uuid"

    .line 15
    .line 16
    sput-object v0, Lz81/p;->b:Ljava/lang/String;

    .line 17
    .line 18
    sget-object v0, La91/a;->a:La91/a;

    .line 19
    .line 20
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 21
    .line 22
    .line 23
    return-void
.end method
