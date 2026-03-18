.class public final Lc7/i;
.super Landroidx/glance/appwidget/protobuf/u;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CHILDREN_FIELD_NUMBER:I = 0x7

.field private static final DEFAULT_INSTANCE:Lc7/i;

.field public static final HASACTION_FIELD_NUMBER:I = 0x9

.field public static final HAS_IMAGE_COLOR_FILTER_FIELD_NUMBER:I = 0xb

.field public static final HAS_IMAGE_DESCRIPTION_FIELD_NUMBER:I = 0xa

.field public static final HEIGHT_FIELD_NUMBER:I = 0x3

.field public static final HORIZONTAL_ALIGNMENT_FIELD_NUMBER:I = 0x4

.field public static final IDENTITY_FIELD_NUMBER:I = 0x8

.field public static final IMAGE_SCALE_FIELD_NUMBER:I = 0x6

.field private static volatile PARSER:Landroidx/glance/appwidget/protobuf/r0; = null
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/glance/appwidget/protobuf/r0;"
        }
    .end annotation
.end field

.field public static final TYPE_FIELD_NUMBER:I = 0x1

.field public static final VERTICAL_ALIGNMENT_FIELD_NUMBER:I = 0x5

.field public static final WIDTH_FIELD_NUMBER:I = 0x2


# instance fields
.field private children_:Landroidx/glance/appwidget/protobuf/x;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/glance/appwidget/protobuf/x;"
        }
    .end annotation
.end field

.field private hasAction_:Z

.field private hasImageColorFilter_:Z

.field private hasImageDescription_:Z

.field private height_:I

.field private horizontalAlignment_:I

.field private identity_:I

.field private imageScale_:I

.field private type_:I

.field private verticalAlignment_:I

.field private width_:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lc7/i;

    .line 2
    .line 3
    invoke-direct {v0}, Lc7/i;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc7/i;->DEFAULT_INSTANCE:Lc7/i;

    .line 7
    .line 8
    const-class v1, Lc7/i;

    .line 9
    .line 10
    invoke-static {v1, v0}, Landroidx/glance/appwidget/protobuf/u;->i(Ljava/lang/Class;Landroidx/glance/appwidget/protobuf/u;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/glance/appwidget/protobuf/u;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Landroidx/glance/appwidget/protobuf/t0;->g:Landroidx/glance/appwidget/protobuf/t0;

    .line 5
    .line 6
    iput-object v0, p0, Lc7/i;->children_:Landroidx/glance/appwidget/protobuf/x;

    .line 7
    .line 8
    return-void
.end method

.method public static k(Lc7/i;Lc7/j;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    sget-object v0, Lc7/j;->n:Lc7/j;

    .line 5
    .line 6
    if-eq p1, v0, :cond_0

    .line 7
    .line 8
    iget p1, p1, Lc7/j;->d:I

    .line 9
    .line 10
    iput p1, p0, Lc7/i;->type_:I

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    const-string p1, "Can\'t get the number of an unknown enum value."

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static l(Lc7/i;Lc7/b;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Lc7/b;->getNumber()I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    iput p1, p0, Lc7/i;->width_:I

    .line 9
    .line 10
    return-void
.end method

.method public static m(Lc7/i;Lc7/b;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Lc7/b;->getNumber()I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    iput p1, p0, Lc7/i;->height_:I

    .line 9
    .line 10
    return-void
.end method

.method public static n(Lc7/i;Lc7/c;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    sget-object v0, Lc7/c;->h:Lc7/c;

    .line 5
    .line 6
    if-eq p1, v0, :cond_0

    .line 7
    .line 8
    iget p1, p1, Lc7/c;->d:I

    .line 9
    .line 10
    iput p1, p0, Lc7/i;->horizontalAlignment_:I

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    const-string p1, "Can\'t get the number of an unknown enum value."

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static o(Lc7/i;Lc7/k;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    sget-object v0, Lc7/k;->h:Lc7/k;

    .line 5
    .line 6
    if-eq p1, v0, :cond_0

    .line 7
    .line 8
    iget p1, p1, Lc7/k;->d:I

    .line 9
    .line 10
    iput p1, p0, Lc7/i;->verticalAlignment_:I

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    const-string p1, "Can\'t get the number of an unknown enum value."

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static p(Lc7/i;Lc7/a;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    sget-object v0, Lc7/a;->h:Lc7/a;

    .line 5
    .line 6
    if-eq p1, v0, :cond_0

    .line 7
    .line 8
    iget p1, p1, Lc7/a;->d:I

    .line 9
    .line 10
    iput p1, p0, Lc7/i;->imageScale_:I

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    const-string p1, "Can\'t get the number of an unknown enum value."

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static q(Lc7/i;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    iput v0, p0, Lc7/i;->identity_:I

    .line 6
    .line 7
    return-void
.end method

.method public static r(Lc7/i;Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lc7/i;->hasAction_:Z

    .line 2
    .line 3
    return-void
.end method

.method public static s(Lc7/i;Ljava/util/ArrayList;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lc7/i;->children_:Landroidx/glance/appwidget/protobuf/x;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Landroidx/glance/appwidget/protobuf/b;

    .line 5
    .line 6
    iget-boolean v1, v1, Landroidx/glance/appwidget/protobuf/b;->d:Z

    .line 7
    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    const/16 v1, 0xa

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    mul-int/lit8 v1, v1, 0x2

    .line 20
    .line 21
    :goto_0
    check-cast v0, Landroidx/glance/appwidget/protobuf/t0;

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Landroidx/glance/appwidget/protobuf/t0;->g(I)Landroidx/glance/appwidget/protobuf/t0;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    iput-object v0, p0, Lc7/i;->children_:Landroidx/glance/appwidget/protobuf/x;

    .line 28
    .line 29
    :cond_1
    iget-object p0, p0, Lc7/i;->children_:Landroidx/glance/appwidget/protobuf/x;

    .line 30
    .line 31
    sget-object v0, Landroidx/glance/appwidget/protobuf/y;->a:Ljava/nio/charset/Charset;

    .line 32
    .line 33
    instance-of v0, p0, Ljava/util/ArrayList;

    .line 34
    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    move-object v0, p0

    .line 38
    check-cast v0, Ljava/util/ArrayList;

    .line 39
    .line 40
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    add-int/2addr v2, v1

    .line 49
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->ensureCapacity(I)V

    .line 50
    .line 51
    .line 52
    :cond_2
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_5

    .line 65
    .line 66
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    if-nez v1, :cond_4

    .line 71
    .line 72
    new-instance p1, Ljava/lang/StringBuilder;

    .line 73
    .line 74
    const-string v1, "Element at index "

    .line 75
    .line 76
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    sub-int/2addr v1, v0

    .line 84
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string v1, " is null."

    .line 88
    .line 89
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    add-int/lit8 v1, v1, -0x1

    .line 101
    .line 102
    :goto_2
    if-lt v1, v0, :cond_3

    .line 103
    .line 104
    invoke-interface {p0, v1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    add-int/lit8 v1, v1, -0x1

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    .line 111
    .line 112
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    :cond_4
    invoke-interface {p0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    goto :goto_1

    .line 120
    :cond_5
    return-void
.end method

.method public static t(Lc7/i;Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lc7/i;->hasImageDescription_:Z

    .line 2
    .line 3
    return-void
.end method

.method public static u(Lc7/i;Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lc7/i;->hasImageColorFilter_:Z

    .line 2
    .line 3
    return-void
.end method

.method public static v()Lc7/i;
    .locals 1

    .line 1
    sget-object v0, Lc7/i;->DEFAULT_INSTANCE:Lc7/i;

    .line 2
    .line 3
    return-object v0
.end method

.method public static w()Lc7/h;
    .locals 2

    .line 1
    sget-object v0, Lc7/i;->DEFAULT_INSTANCE:Lc7/i;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-virtual {v0, v1}, Lc7/i;->b(I)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Landroidx/glance/appwidget/protobuf/s;

    .line 9
    .line 10
    check-cast v0, Lc7/h;

    .line 11
    .line 12
    return-object v0
.end method


# virtual methods
.method public final b(I)Ljava/lang/Object;
    .locals 12

    .line 1
    invoke-static {p1}, Lu/w;->o(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    sget-object p0, Lc7/i;->PARSER:Landroidx/glance/appwidget/protobuf/r0;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    const-class p1, Lc7/i;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object p0, Lc7/i;->PARSER:Landroidx/glance/appwidget/protobuf/r0;

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    new-instance p0, Landroidx/glance/appwidget/protobuf/t;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    sput-object p0, Lc7/i;->PARSER:Landroidx/glance/appwidget/protobuf/r0;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception v0

    .line 34
    move-object p0, v0

    .line 35
    goto :goto_1

    .line 36
    :cond_0
    :goto_0
    monitor-exit p1

    .line 37
    return-object p0

    .line 38
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    throw p0

    .line 40
    :cond_1
    return-object p0

    .line 41
    :pswitch_1
    sget-object p0, Lc7/i;->DEFAULT_INSTANCE:Lc7/i;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_2
    new-instance p0, Lc7/h;

    .line 45
    .line 46
    sget-object p1, Lc7/i;->DEFAULT_INSTANCE:Lc7/i;

    .line 47
    .line 48
    invoke-direct {p0, p1}, Landroidx/glance/appwidget/protobuf/s;-><init>(Landroidx/glance/appwidget/protobuf/u;)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_3
    new-instance p0, Lc7/i;

    .line 53
    .line 54
    invoke-direct {p0}, Lc7/i;-><init>()V

    .line 55
    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_4
    const-string v0, "type_"

    .line 59
    .line 60
    const-string v1, "width_"

    .line 61
    .line 62
    const-string v2, "height_"

    .line 63
    .line 64
    const-string v3, "horizontalAlignment_"

    .line 65
    .line 66
    const-string v4, "verticalAlignment_"

    .line 67
    .line 68
    const-string v5, "imageScale_"

    .line 69
    .line 70
    const-string v6, "children_"

    .line 71
    .line 72
    const-class v7, Lc7/i;

    .line 73
    .line 74
    const-string v8, "identity_"

    .line 75
    .line 76
    const-string v9, "hasAction_"

    .line 77
    .line 78
    const-string v10, "hasImageDescription_"

    .line 79
    .line 80
    const-string v11, "hasImageColorFilter_"

    .line 81
    .line 82
    filled-new-array/range {v0 .. v11}, [Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    const-string p1, "\u0000\u000b\u0000\u0000\u0001\u000b\u000b\u0000\u0001\u0000\u0001\u000c\u0002\u000c\u0003\u000c\u0004\u000c\u0005\u000c\u0006\u000c\u0007\u001b\u0008\u000c\t\u0007\n\u0007\u000b\u0007"

    .line 87
    .line 88
    sget-object v0, Lc7/i;->DEFAULT_INSTANCE:Lc7/i;

    .line 89
    .line 90
    new-instance v1, Landroidx/glance/appwidget/protobuf/u0;

    .line 91
    .line 92
    invoke-direct {v1, v0, p1, p0}, Landroidx/glance/appwidget/protobuf/u0;-><init>(Landroidx/glance/appwidget/protobuf/u;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    return-object v1

    .line 96
    :pswitch_5
    const/4 p0, 0x0

    .line 97
    return-object p0

    .line 98
    :pswitch_6
    const/4 p0, 0x1

    .line 99
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0

    .line 104
    nop

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
