.class public final Le2/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le2/l;


# instance fields
.field public final synthetic a:Le2/w0;

.field public final synthetic b:Z


# direct methods
.method public constructor <init>(Le2/w0;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le2/y0;->a:Le2/w0;

    .line 5
    .line 6
    iput-boolean p2, p0, Le2/y0;->b:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()J
    .locals 2

    .line 1
    iget-object v0, p0, Le2/y0;->a:Le2/w0;

    .line 2
    .line 3
    iget-boolean p0, p0, Le2/y0;->b:Z

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Le2/w0;->k(Z)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method
