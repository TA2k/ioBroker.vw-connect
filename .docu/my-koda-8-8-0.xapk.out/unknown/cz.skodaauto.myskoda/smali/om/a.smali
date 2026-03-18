.class public abstract Lom/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lu01/i;

.field public static final b:Lu01/i;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lu01/i;->g:Lu01/i;

    .line 2
    .line 3
    const-string v0, "<svg"

    .line 4
    .line 5
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lom/a;->a:Lu01/i;

    .line 10
    .line 11
    const-string v0, "<"

    .line 12
    .line 13
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lom/a;->b:Lu01/i;

    .line 18
    .line 19
    return-void
.end method
