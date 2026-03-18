.class public final synthetic La8/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm8/x;


# instance fields
.field public final synthetic d:La8/q0;

.field public final synthetic e:Lm8/x;


# direct methods
.method public synthetic constructor <init>(La8/q0;Lm8/x;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La8/k0;->d:La8/q0;

    .line 5
    .line 6
    iput-object p2, p0, La8/k0;->e:Lm8/x;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(JJLt7/o;Landroid/media/MediaFormat;)V
    .locals 7

    .line 1
    move-object v0, p0

    .line 2
    iget-object p0, v0, La8/k0;->d:La8/q0;

    .line 3
    .line 4
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    iget-object v0, v0, La8/k0;->e:Lm8/x;

    .line 8
    .line 9
    move-wide v1, p1

    .line 10
    move-wide v3, p3

    .line 11
    move-object v5, p5

    .line 12
    move-object v6, p6

    .line 13
    invoke-interface/range {v0 .. v6}, Lm8/x;->b(JJLt7/o;Landroid/media/MediaFormat;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual/range {p0 .. p6}, La8/q0;->b(JJLt7/o;Landroid/media/MediaFormat;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method
